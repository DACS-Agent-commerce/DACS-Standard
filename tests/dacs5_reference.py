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
import copy
import hashlib
import json
import math
import re
import unicodedata
from decimal import Decimal, InvalidOperation
from urllib.parse import quote, urlsplit

from scripts.jcs import canonicalize as jcs_canonicalize
from scripts.settlement_finality_reference import verify_finality

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - environment-dependent
    HAVE_CRYPTO = False

BUNDLE_DOMAIN = "dacs-bundle:v1:"
FAULT_BUNDLE_DOMAIN = "dacs-fault-bundle:v1:"
EVIDENCE_BOUND_FAULT_BUNDLE_DOMAIN = "dacs-evidence-bound-fault-bundle:v1:"
FINALITY_BOUND_EVIDENCE_FAULT_BUNDLE_DOMAIN = "dacs-finality-bound-evidence-fault-bundle:v1:"
LISTING_DOMAIN = "dacs-listing:v1:"
SETTLEMENT_EVIDENCE_DOMAIN = "dacs-evidence:v1:"
FINALITY_BOUND_SETTLEMENT_EVIDENCE_DOMAIN = "dacs-finality-bound-evidence:v1:"
BINDING_DOMAIN = "dacs-bundle-binding:v1:"
FAULT_POINTER_DOMAIN = "dacs-fault-bundle-pointer:v1:"
EVIDENCE_BOUND_FAULT_POINTER_DOMAIN = "dacs-evidence-bound-fault-bundle-pointer:v1:"
FINALITY_BOUND_EVIDENCE_FAULT_POINTER_DOMAIN = "dacs-finality-bound-evidence-fault-bundle-pointer:v1:"
LEGACY_BUNDLE_CHECKPOINT_DOMAIN = "dacs-legacy-bundle-checkpoint:v1:"
LEGACY_BUNDLE_CHECKPOINT_BINDING_DOMAIN = "dacs-legacy-bundle-checkpoint-binding:v1:"
RATING_DOMAIN = "dacs-rating:v1:"

# These two domains are deliberately fixture-only.  They authenticate the synthetic
# native observations used by this offline executable reference; they are not DACS
# artifact domains and do not claim to specify a production substrate proof codec.
CURRENT_USE_SYNTHETIC_ANCHOR_PROOF_DOMAIN = "dacs-current-use-synthetic-anchor-proof:v1:"
CURRENT_USE_SYNTHETIC_SETTLEMENT_BINDING_PROOF_DOMAIN = (
    "dacs-current-use-synthetic-settlement-binding-proof:v1:"
)

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
    """RFC 8785-style JCS: sorted keys, tight separators, non-ASCII preserved."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _new_type_canonical(value):
    """Shared RFC 8785 JCS for #392 artifacts; released hashes stay untouched."""
    return jcs_canonicalize(value).encode("utf-8")


def bundle_hash(bundle):
    """§10.4.1 attestation_bundle_hash: canonical form minus signatures + anchoredByRole,
    computed identically for AttestationBundle and FaultAttestationBundle."""
    unsigned = {k: v for k, v in bundle.items() if k not in ("signatures", "anchoredByRole")}
    encoded = (
        _new_type_canonical(unsigned)
        if isinstance(bundle, dict) and "finalityBoundEvidenceFaultBundleVersion" in bundle
        else canonical(unsigned)
    )
    return hashlib.sha256(encoded).hexdigest()


def listing_hash(listing):
    """§6.3.4 listing hash: canonical form minus the signature envelope."""
    unsigned = {k: v for k, v in listing.items() if k != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def settlement_evidence_hash(record):
    """DACS-4 §9.7 evidence hash: canonical form minus its signature envelope."""
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    encoded = (
        _new_type_canonical(unsigned)
        if isinstance(record, dict) and "finalityBoundEvidenceVersion" in record
        else canonical(unsigned)
    )
    return hashlib.sha256(encoded).hexdigest()


def binding_hash(binding):
    unsigned = {k: v for k, v in binding.items() if k != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def pointer_hash(pointer):
    """FaultBundleExtendedPointer signed-scope hash (E7): canonical form minus signature."""
    unsigned = {k: v for k, v in pointer.items() if k != "signature"}
    encoded = (
        _new_type_canonical(unsigned)
        if isinstance(pointer, dict) and "finalityBoundEvidenceFaultBundleVersion" in pointer
        else canonical(unsigned)
    )
    return hashlib.sha256(encoded).hexdigest()


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
    """Return the exact supported §10.4 discriminator class or None.

    Discriminators are exclusive. Unknown, stripped, or multiply-labelled objects do not
    inherit a legacy type merely because one verifier happens to recognize fewer fields.
    """
    if not isinstance(bundle, dict):
        return None
    candidates = []
    if bundle.get("bundleVersion") == "1":
        candidates.append("legacy")
    if bundle.get("faultBundleVersion") == "1":
        candidates.append("fault")
    if bundle.get("evidenceBoundFaultBundleVersion") == "1":
        candidates.append("evidence-bound")
    if bundle.get("finalityBoundEvidenceFaultBundleVersion") == "1":
        candidates.append("finality-bound")
    known_keys = {
        "bundleVersion",
        "faultBundleVersion",
        "evidenceBoundFaultBundleVersion",
        "finalityBoundEvidenceFaultBundleVersion",
    }
    unknown_discriminators = {
        key for key in bundle
        if isinstance(key, str) and key.endswith("BundleVersion") and key not in known_keys
    }
    if unknown_discriminators:
        return None
    if any(key in bundle and bundle.get(key) != "1" for key in known_keys):
        return None
    return candidates[0] if len(candidates) == 1 else None


def bundle_type_rank(bundle):
    return {"legacy": 0, "fault": 1, "evidence-bound": 2, "finality-bound": 3}.get(bundle_type(bundle), -1)


def bundle_domain(bundle):
    kind = bundle_type(bundle)
    if kind == "legacy":
        return BUNDLE_DOMAIN
    if kind == "fault":
        return FAULT_BUNDLE_DOMAIN
    if kind == "evidence-bound":
        return EVIDENCE_BOUND_FAULT_BUNDLE_DOMAIN
    if kind == "finality-bound":
        return FINALITY_BOUND_EVIDENCE_FAULT_BUNDLE_DOMAIN
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
    except InvalidSignature:
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
    """True for an absolute-fault bundle type."""
    return bundle_type(bundle) in {"fault", "evidence-bound", "finality-bound"}


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

    if bundle_type(copy_a) == bundle_type(copy_b) and bundle_type(copy_a) in {
        "evidence-bound", "finality-bound",
    }:
        encode = _new_type_canonical if bundle_type(copy_a) == "finality-bound" else canonical
        refs_a = {encode(ref) for ref in copy_a.get("settlementEvidence", [])}
        refs_b = {encode(ref) for ref in copy_b.get("settlementEvidence", [])}
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


def _bundle_signatures_valid(bundle, pubkeys):
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
    if bundle_type(bundle) is None:
        return (False, "unsupported, missing, or non-exclusive bundle discriminator")
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


def _validate_evidence_resolution_binding(ref, execution, receipt, bundle, phase_index,
                                          phase_kind, signer, *, resolved=False):
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
    else:
        expected_logical = execution.get("evidenceLogicalAddress")
        if not isinstance(expected_logical, str) or not expected_logical:
            return (False, "delivery execution authority lacks evidenceLogicalAddress")
    anchor = ref.get("anchor") if isinstance(ref, dict) else None
    nonce = receipt.get("nonce")
    expected_nonce = execution.get("anchorNonce")
    if (
        receipt.get("logicalAddress") != expected_logical
        or not isinstance(anchor, dict)
        or receipt.get("nativeAddress") != anchor.get("locator")
        or receipt.get("contentHash") != ref.get("contentHash")
        or not isinstance(receipt.get("transaction"), str)
        or not receipt["transaction"]
        or receipt.get("writer") != signer
        or not (
            (isinstance(nonce, str) and bool(nonce))
            or (
                isinstance(nonce, int)
                and not isinstance(nonce, bool)
                and nonce >= 0
            )
        )
        or (expected_nonce is not None and nonce != expected_nonce)
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


def _finality_payment_tx_refs_match_phase(phase, refs):
    """Exact strong-evidence transaction cardinality, including both HTLC locks."""
    if phase != "pay-cross-chain-htlc":
        return _payment_tx_refs_match_phase(phase, refs, success=True)
    kinds = [ref["kind"] for ref in refs]
    return (
        len(kinds) == 4
        and kinds.count("htlc-lock") == 2
        and kinds.count("htlc-claim") == 1
        and kinds.count("htlc-reveal") == 1
    )


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


def _finality_bound_settlement_evidence_shape_valid(record):
    """Closed shape for the distinct #392 successful-payment evidence type.

    This does not project the object into the legacy SettlementEvidence shape. The
    finality verifier subsequently authenticates every signed field and proof binding.
    """
    if not isinstance(record, dict):
        return False
    required = {
        "finalityBoundEvidenceVersion", "jobId", "phase", "outcome",
        "paymentTxRefs", "paymentAmount", "settlementFinality",
        "railDefinitionRef", "observedAt", "signature",
    }
    optional = {"paymentFee", "amendmentRefs", "supersedesEvidenceRef"}
    unknown_discriminators = {
        key for key in record
        if isinstance(key, str)
        and key.endswith("EvidenceVersion")
        and key != "finalityBoundEvidenceVersion"
    }
    if (
        set(record) - required - optional
        or not required <= set(record)
        or unknown_discriminators
        or record.get("finalityBoundEvidenceVersion") != "1"
        or not _nonempty_jcs_string(record.get("jobId"))
        or not _string_member(record.get("phase"), PAYMENT_PHASES)
        or record.get("outcome") != "success"
        or not _non_boolean_number(record.get("observedAt"))
        or not _price_term_shape_valid(record.get("paymentAmount"))
        or not isinstance(record.get("paymentTxRefs"), list)
        or not record["paymentTxRefs"]
        or any(not _chain_tx_ref_shape_valid(ref) for ref in record["paymentTxRefs"])
        or not _finality_payment_tx_refs_match_phase(record["phase"], record["paymentTxRefs"])
        or not _settlement_finality_shape_valid(record.get("settlementFinality"))
        or not _settlement_finality_matches_phase(
            record["phase"], record["settlementFinality"], record["paymentTxRefs"]
        )
    ):
        return False
    signature = record.get("signature")
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "signer", "value"}
        or signature.get("algorithm") != "ed25519"
        or not _claim_reference_shape_valid(signature.get("signer"))
        or not _nonempty_jcs_string(signature.get("value"))
    ):
        return False
    rail_ref = record.get("railDefinitionRef")
    anchor = rail_ref.get("anchor") if isinstance(rail_ref, dict) else None
    if (
        not isinstance(rail_ref, dict)
        or set(rail_ref) != {"anchor", "contentHash", "railId", "railVersion"}
        or not isinstance(anchor, dict)
        or set(anchor) != {"kind", "locator"}
        or not _string_member(anchor.get("kind"), SUPPORTED_ATTESTATION_ANCHOR_KINDS)
        or not _nonempty_jcs_string(anchor.get("locator"))
        or not _sha256_hex(rail_ref.get("contentHash"))
        or not _nonempty_jcs_string(rail_ref.get("railId"))
        or not _safe_nonnegative_integer(rail_ref.get("railVersion"), positive=True)
    ):
        return False
    if "paymentFee" in record and not _price_term_shape_valid(record["paymentFee"]):
        return False
    if "amendmentRefs" in record and (
        not isinstance(record["amendmentRefs"], list)
        or any(not _attestation_ref_shape_valid(ref) for ref in record["amendmentRefs"])
    ):
        return False
    return (
        "supersedesEvidenceRef" not in record
        or _attestation_ref_shape_valid(record["supersedesEvidenceRef"])
    )


def _resolve_authenticated_evidence_binding(ref, record, signer, bundle,
                                            session_execution_authority_by_phase_key,
                                            verified_receipt_by_canonical_ref):
    """Resolve one exact phase from trusted SB-1 authority plus verified SR-2 receipt evidence."""
    ref_key = canonical(ref).decode("utf-8")
    receipt = verified_receipt_by_canonical_ref.get(ref_key)
    if not isinstance(receipt, dict):
        return (False, "settlement evidence lacks a verified SR-2 receipt", None)
    matches = []
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
                resolved=resolved,
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


def _validate_bound_fault_bundle(
    bundle,
    listing,
    pubkeys,
    reference_validation_by_canonical_ref,
    bundle_lifecycle,
    session_execution_authority_by_phase_key,
    verified_receipt_by_canonical_ref,
    *,
    expected_kind,
    effective_pipeline=None,
    additional_commit_phase=None,
):
    """Execute the authenticated SEB gate needed before EBFAB reconciliation.

    This bounded reference covers the protected #290 authority path: exact type/domain
    signatures, content-bound signed listing pipeline, phase-key derivation, the
    settlementEvidence bijection, and the SR-2 lifecycle threshold. It intentionally
    remains test support rather than a general DACS validator.
    """
    if bundle_type(bundle) != expected_kind:
        reason = (
            "not an EvidenceBoundFaultAttestationBundle"
            if expected_kind == "evidence-bound"
            else "not the expected evidence-bound bundle type"
        )
        return (False, reason, None)
    if not _absolute_fault_bundle_shape_valid(bundle):
        reason = (
            "malformed EvidenceBoundFaultAttestationBundle"
            if expected_kind == "evidence-bound"
            else "malformed evidence-bound bundle"
        )
        return (False, reason, None)
    if (
        not isinstance(listing, dict)
        or not isinstance(pubkeys, dict)
        or not isinstance(reference_validation_by_canonical_ref, dict)
        or not isinstance(bundle_lifecycle, dict)
        or not isinstance(session_execution_authority_by_phase_key, dict)
        or not isinstance(verified_receipt_by_canonical_ref, dict)
    ):
        return (False, "missing listing, key, exact reference, or bundle-lifecycle authority", None)
    ok, reason = _bundle_signatures_valid(bundle, pubkeys)
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
    for ref, resolution in zip(actual_refs, exact_resolutions):
        record = resolution.get("record")
        if not isinstance(record, dict):
            return (False, "settlement evidence lacks authenticated record", None)
        signature = record.get("signature")
        record_is_finality_bound = (
            expected_kind == "finality-bound"
            and record.get("phase") in PAYMENT_PHASES
            and record.get("outcome") == "success"
        )
        shape_valid = (
            _finality_bound_settlement_evidence_shape_valid(record)
            if record_is_finality_bound
            else _settlement_evidence_shape_valid(record)
        )
        evidence_domain = (
            FINALITY_BOUND_SETTLEMENT_EVIDENCE_DOMAIN
            if record_is_finality_bound
            else SETTLEMENT_EVIDENCE_DOMAIN
        )
        if not shape_valid:
            if record_is_finality_bound:
                return (False, "malformed finality-bound settlement evidence record", None)
            return (False, "settlement evidence record does not bind this job, phase, signer, or hash", None)
        if (
            record.get("jobId") != bundle.get("jobId")
            or not isinstance(signature, dict)
            or signature.get("algorithm") != "ed25519"
            or not isinstance(signature.get("signer"), str)
            or signature.get("signer") not in pubkeys
            or ref.get("contentHash") != settlement_evidence_hash(record)
        ):
            return (False, "settlement evidence record does not bind this job, phase, signer, or hash", None)
        canonical_ok, canonical_reason = sig6_canonical(signature.get("value", ""))
        if not canonical_ok:
            return (False, canonical_reason, None)
        if not verify_sig(
            pubkeys[signature["signer"]],
            evidence_domain,
            settlement_evidence_hash(record),
            signature["value"],
        ):
            return (False, "settlement evidence signature does not verify", None)
        binding_ok, binding_result, _ = _resolve_authenticated_evidence_binding(
            ref,
            record,
            signature["signer"],
            bundle,
            session_execution_authority_by_phase_key,
            verified_receipt_by_canonical_ref,
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
            return (False, "settlement evidence record contradicts the signed phase result", None)
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
    for resolution in exact_resolutions:
        lifecycle = resolution.get("lifecycle")
        if not isinstance(lifecycle, dict):
            return (False, "settlement evidence lacks authenticated lifecycle", None)
        state = lifecycle.get("state")
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
    return (True, "ok", expected_keys)


def validate_ebfab(
    bundle,
    listing,
    pubkeys,
    reference_validation_by_canonical_ref,
    bundle_lifecycle,
    session_execution_authority_by_phase_key,
    verified_receipt_by_canonical_ref,
    *,
    effective_pipeline=None,
    additional_commit_phase=None,
):
    """Execute the released EvidenceBoundFaultAttestationBundle contract unchanged."""
    return _validate_bound_fault_bundle(
        bundle,
        listing,
        pubkeys,
        reference_validation_by_canonical_ref,
        bundle_lifecycle,
        session_execution_authority_by_phase_key,
        verified_receipt_by_canonical_ref,
        expected_kind="evidence-bound",
        effective_pipeline=effective_pipeline,
        additional_commit_phase=additional_commit_phase,
    )


def validate_finality_bound_ebfab(
    bundle,
    listing,
    pubkeys,
    reference_validation_by_canonical_ref,
    bundle_lifecycle,
    session_execution_authority_by_phase_key,
    verified_receipt_by_canonical_ref,
    finality_verification_by_canonical_ref,
    finality_trust,
    *,
    effective_pipeline=None,
    additional_commit_phase=None,
):
    """Execute the distinct finality-bound bundle consumer and propagate FV decisions.

    Returns ``(decision, reason, phase_keys)`` where decision is one of pass,
    fail, indeterminate, or error. A strong signed object is never rewritten as
    legacy evidence to enter the older validator.
    """
    if bundle_type(bundle) != "finality-bound":
        return ("error", "not a FinalityBoundEvidenceFaultAttestationBundle", None)
    if not isinstance(finality_verification_by_canonical_ref, dict):
        return ("indeterminate", "finality verification authority is unavailable", None)
    if not isinstance(finality_trust, dict):
        return ("indeterminate", "trusted finality policy is unavailable", None)
    references = bundle.get("settlementEvidence")
    if (
        isinstance(reference_validation_by_canonical_ref, dict)
        and isinstance(references, list)
        and all(isinstance(ref, dict) for ref in references)
    ):
        reference_keys = [canonical(ref).decode("utf-8") for ref in references]
        if any(key not in reference_validation_by_canonical_ref for key in reference_keys):
            return ("indeterminate", "referenced shared SEB authority is unavailable", None)
    ok, reason, phase_keys = _validate_bound_fault_bundle(
        bundle,
        listing,
        pubkeys,
        reference_validation_by_canonical_ref,
        bundle_lifecycle,
        session_execution_authority_by_phase_key,
        verified_receipt_by_canonical_ref,
        expected_kind="finality-bound",
        effective_pipeline=effective_pipeline,
        additional_commit_phase=additional_commit_phase,
    )
    if not ok:
        if reason == "missing listing, key, exact reference, or bundle-lifecycle authority":
            return ("indeterminate", "shared SEB authority is unavailable", None)
        malformed = reason.startswith(("not the expected", "malformed", "pipeline or"))
        return ("error" if malformed else "fail", reason, None)

    results = []
    for ref in bundle.get("settlementEvidence", []):
        ref_key = canonical(ref).decode("utf-8")
        resolution = reference_validation_by_canonical_ref.get(ref_key)
        record = resolution.get("record") if isinstance(resolution, dict) else None
        if not (
            isinstance(record, dict)
            and record.get("phase") in PAYMENT_PHASES
            and record.get("outcome") == "success"
        ):
            continue
        candidate = finality_verification_by_canonical_ref.get(ref_key)
        if not isinstance(candidate, dict):
            results.append(("indeterminate", "successful payment lacks finality verification input"))
            continue
        if candidate.get("evidence") != record:
            results.append(("fail", "finality input does not bind the exact authenticated evidence"))
            continue
        agreement = candidate.get("agreement")
        if not isinstance(agreement, dict):
            results.append(("error", "finality agreement is not an object"))
            continue
        finality_result = verify_finality(candidate, finality_trust)
        decision = finality_result["decision"]
        finality_class = finality_result.get("finalityClass")
        detail = finality_result["reason"]
        if decision == "error":
            results.append((decision, "FV rejected successful payment: " + detail))
            continue
        if agreement.get("listingRef") != bundle.get("listingRef"):
            results.append(("fail", "authenticated agreement binds a different listing"))
            continue
        if decision != "pass":
            results.append((decision, "FV rejected successful payment: " + detail))
        elif finality_class not in {"profile-final", "provisional-provider-capture"}:
            results.append(("error", "FV returned an unsupported passing finality class"))

    for precedence in ("error", "fail", "indeterminate"):
        for decision, detail in results:
            if decision == precedence:
                return (decision, detail, None)
    return ("pass", "authenticated SEB and finality verification passed", phase_keys)


def reconcile_authenticated_finality_copies(entries, pubkeys, finality_trust):
    """Reconcile authenticated new/new and new/older copies before type precedence.

    A present entry carries ``bundle``, trusted ``expectedJobId``/``expectedRole``,
    and the appropriate ``authority`` for evidence-bound types. A separately trusted
    resolver can instead report ``disposition`` as ``absent`` or ``indeterminate``;
    those are consumer inputs, never producer-authored verification booleans. The
    helper is a bounded executable consumer interface for #392; it is not by
    itself the combined #391+#392 reputation derivation implemented below.
    """
    if not isinstance(entries, list) or not entries:
        return {"decision": "error", "reason": "copy set must be a non-empty array", "bundle": None}
    if not isinstance(pubkeys, dict) or not isinstance(finality_trust, dict):
        return {"decision": "indeterminate", "reason": "copy authentication authority unavailable", "bundle": None}

    requested_jobs = set()
    requested_roles_by_job = {}
    authenticated = []
    nonpasses = []
    for entry in entries:
        if not isinstance(entry, dict):
            return {"decision": "error", "reason": "copy entry is not an object", "bundle": None}
        expected_job = entry.get("expectedJobId")
        expected_role = entry.get("expectedRole")
        if (
            not isinstance(expected_job, str)
            or not expected_job
            or not _string_member(expected_role, {"buyer", "seller", "orchestrator"})
        ):
            nonpasses.append((None, "error", "copy request job or role authority is malformed"))
            continue
        requested_jobs.add(expected_job)
        requested_roles_by_job.setdefault(expected_job, set()).add(expected_role)
        disposition = entry.get("disposition", "present")
        if disposition == "absent":
            trusted_dispositions = finality_trust.get("copyDispositionByJobRole")
            key = expected_job + ":" + expected_role
            if not (
                isinstance(trusted_dispositions, dict)
                and trusted_dispositions.get(key) == "absent"
            ):
                nonpasses.append((None, "indeterminate", "copy absence is not authenticated"))
            continue
        if disposition == "indeterminate":
            nonpasses.append((None, "indeterminate", "copy presence is indeterminate"))
            continue
        if disposition != "present":
            nonpasses.append((None, "error", "copy disposition is unsupported"))
            continue
        bundle = entry.get("bundle")
        kind = bundle_type(bundle)
        if (
            kind is None
            or not isinstance(bundle, dict)
            or bundle.get("jobId") != expected_job
            or bundle.get("anchoredByRole") != expected_role
        ):
            decision = "error" if kind is None else "fail"
            nonpasses.append((kind, decision, "copy type, job, or authenticated role binding is invalid"))
            continue
        # Reject malformed decoded bytes before unavailable presence authority
        # can hide the error or canonical hashing can raise.
        try:
            shape_ok = (
                _absolute_fault_bundle_shape_valid(bundle)
                if kind in {"finality-bound", "evidence-bound", "fault"}
                else _bundle_shape_ok(bundle)[0]
            )
            exact_bundle_hash = bundle_hash(bundle) if shape_ok else None
        except (TypeError, ValueError, UnicodeError, RecursionError):
            shape_ok = False
        if not shape_ok:
            nonpasses.append((kind, "error", "malformed copy bundle"))
            continue
        trusted_presence = finality_trust.get("copyPresenceByJobRole")
        key = expected_job + ":" + expected_role
        presence = entry.get("copyPresence")
        parties = bundle.get("parties")
        role_party = next(
            (
                party for party in parties
                if isinstance(party, dict) and party.get("role") == expected_role
            ),
            None,
        )
        if not (
            isinstance(trusted_presence, dict)
            and isinstance(presence, dict)
            and trusted_presence.get(key) == presence
        ):
            nonpasses.append((kind, "indeterminate", "present copy authority is unavailable"))
            continue
        if not (
            set(presence) == {"bundleHash", "nativeAddress", "writer"}
            and presence.get("bundleHash") == exact_bundle_hash
            and isinstance(presence.get("nativeAddress"), str)
            and presence.get("nativeAddress")
            and isinstance(role_party, dict)
            and presence.get("writer") == role_party.get("primaryClaim")
        ):
            nonpasses.append((kind, "fail", "present copy role or address binding is invalid"))
            continue
        authority = entry.get("authority")
        if kind == "finality-bound":
            if not isinstance(authority, dict):
                result = ("indeterminate", "strong copy authority unavailable", None)
            else:
                result = validate_finality_bound_ebfab(
                    bundle,
                    authority.get("listing"),
                    pubkeys,
                    authority.get("referenceValidationByCanonicalRef"),
                    authority.get("bundleLifecycle"),
                    authority.get("sessionExecutionAuthorityByPhaseKey"),
                    authority.get("verifiedReceiptByCanonicalRef"),
                    authority.get("finalityVerificationByCanonicalRef"),
                    finality_trust,
                    effective_pipeline=authority.get("effectivePipeline"),
                    additional_commit_phase=authority.get("additionalCommitPhase"),
                )
            if result[0] != "pass":
                nonpasses.append((kind, result[0], result[1]))
                continue
        elif kind == "evidence-bound":
            if not isinstance(authority, dict):
                nonpasses.append((kind, "indeterminate", "EBFAB authority unavailable"))
                continue
            ok, reason, _ = validate_ebfab(
                bundle,
                authority.get("listing"),
                pubkeys,
                authority.get("referenceValidationByCanonicalRef"),
                authority.get("bundleLifecycle"),
                authority.get("sessionExecutionAuthorityByPhaseKey"),
                authority.get("verifiedReceiptByCanonicalRef"),
                effective_pipeline=authority.get("effectivePipeline"),
                additional_commit_phase=authority.get("additionalCommitPhase"),
            )
            if not ok:
                nonpasses.append((kind, "fail", reason))
                continue
        else:
            shape_ok = (
                _absolute_fault_bundle_shape_valid(bundle)
                if kind == "fault"
                else _bundle_shape_ok(bundle)[0]
            )
            signatures_ok, reason = _bundle_signatures_valid(bundle, pubkeys)
            if not shape_ok or not signatures_ok:
                nonpasses.append((kind, "fail", reason if not signatures_ok else "malformed older bundle"))
                continue
        authenticated.append(bundle)

    # A present strong copy that cannot establish its required proof is never
    # replaced by an otherwise-valid weaker representation of the same job.
    if len(requested_jobs) != 1:
        return {"decision": "fail", "reason": "copy requests bind different jobs", "bundle": None}
    # A resolver must supply an authenticated presence disposition for both
    # role-addresses. Omitting one side is not authoritative absence, and
    # duplicate copies from one side cannot stand in for the other side.
    requested_job = next(iter(requested_jobs))
    for scoped in (
        [item for item in nonpasses if item[0] == "finality-bound"],
        nonpasses,
    ):
        for precedence in ("error", "fail"):
            for _kind, decision, reason in scoped:
                if decision == precedence:
                    return {"decision": decision, "reason": reason, "bundle": None}
    if not {"buyer", "seller"} <= requested_roles_by_job[requested_job]:
        return {
            "decision": "indeterminate",
            "reason": "both buyer and seller copy dispositions are required",
            "bundle": None,
        }
    for scoped in (
        [item for item in nonpasses if item[0] == "finality-bound"],
        nonpasses,
    ):
        for _kind, decision, reason in scoped:
            if decision == "indeterminate":
                return {"decision": decision, "reason": reason, "bundle": None}
    if not authenticated:
        return {"decision": "indeterminate", "reason": "no authenticated copies", "bundle": None}
    jobs = {bundle["jobId"] for bundle in authenticated}
    if len(jobs) != 1:
        return {"decision": "fail", "reason": "authenticated copies bind different jobs", "bundle": None}
    for index, left in enumerate(authenticated):
        for right in authenticated[index + 1:]:
            if divergence(left, right):
                return {"decision": "fail", "reason": "authenticated copies diverge", "bundle": None}
    winner = max(
        authenticated,
        key=lambda bundle: (bundle_type_rank(bundle), bundle_hash(bundle)),
    )
    return {"decision": "pass", "reason": "authenticated strongest compatible copy selected", "bundle": winner}


def _tagged_copy_valid_for_derive(tagged):
    """Reject an EBFAB before divergence/ranking unless its authenticated SEB gate passes."""
    bundle = tagged.get("bundle")
    kind = bundle_type(bundle)
    if kind is None:
        return False
    # The combined #391+#392 current-use derivation has not been allocated or
    # implemented. A finality-bound copy cannot enter either released derivation.
    if kind == "finality-bound":
        return False
    if kind != "evidence-bound":
        return True
    authority = tagged.get("ebfabAuthority")
    if not isinstance(authority, dict):
        return False
    ok, _, _ = validate_ebfab(
        bundle,
        authority.get("listing"),
        authority.get("publicKeys"),
        authority.get("referenceValidationByCanonicalRef"),
        authority.get("bundleLifecycle"),
        authority.get("sessionExecutionAuthorityByPhaseKey"),
        authority.get("verifiedReceiptByCanonicalRef"),
        effective_pipeline=authority.get("effectivePipeline"),
        additional_commit_phase=authority.get("additionalCommitPhase"),
    )
    return ok


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


def _post_fetch_address_valid_with_profile(
        fetched, resolved_address, expected_role, expected_content_hash, pubkeys,
        expected_jobid=None, expected_participant=None, *, pure_mapping_resolver,
        job_id_validator):
    """Pure-mapping equivalent of BB-5 post-fetch validation.

    The role is authenticated by recomputing its deterministic logical/native address from the
    fetched jobId rather than by a BundleBinding. The fetched copy still has to satisfy the same
    role, signature, fault-permissibility, and byte-recomputed content-hash checks.
    """
    if not isinstance(fetched, dict):
        return (False, "fetched copy is not an object")
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
            party.get("role") == expected_role for party in parties
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
    if is_fab(fetched):
        roster = roster_roles(fetched)
        try:
            fset = implied_fault_set(fetched.get("outcome"), expected_role, roster)
        except ValueError as exc:
            return (False, "§10.4.1 %s" % (exc,))
        if fetched.get("faultedParty") not in fset:
            return (False, "§10.4.1 faultedParty %r outside the permissible set %r for (%r, %r)"
                    % (fetched.get("faultedParty"), sorted(fset), fetched.get("outcome"), expected_role))
    ok_sig, reason = _bundle_signatures_valid(fetched, pubkeys)
    if not ok_sig:
        return (False, reason)
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


def _finality_bound_fault_bundle_shape_valid(bundle):
    """Closed recursive shape for the unallocated #392 bundle only."""
    required = {
        "finalityBoundEvidenceFaultBundleVersion", "jobId", "outcome", "faultedParty",
        "anchoredByRole", "listingRef", "parties", "phaseSummary", "vetRecords",
        "settlementEvidence", "recipeRegistryVersion", "railRegistryVersion",
        "finalisedAt", "signatures",
    }
    optional = {"agreementRef", "cancellation", "amendments", "ratingRefs"}
    if not isinstance(bundle, dict) or not required <= set(bundle) <= required | optional:
        return False
    listing_ref = bundle.get("listingRef")
    if not (
        bundle.get("finalityBoundEvidenceFaultBundleVersion") == "1"
        and _nonempty_jcs_string(bundle.get("jobId"))
        and _string_member(bundle.get("outcome"), {
            "completed", "failed-perm", "failed-counterparty", "failed-substrate",
            "aborted-by-self", "aborted-by-other",
        })
        and _string_member(bundle.get("faultedParty"), {"buyer", "seller", "orchestrator", "none"})
        and _string_member(bundle.get("anchoredByRole"), {"buyer", "seller", "orchestrator"})
        and isinstance(listing_ref, dict)
        and set(listing_ref) == {"listingId", "version", "contentHash"}
        and _nonempty_jcs_string(listing_ref.get("listingId"))
        and _safe_nonnegative_integer(listing_ref.get("version"), positive=True)
        and _sha256_hex(listing_ref.get("contentHash"))
        and _safe_nonnegative_integer(bundle.get("recipeRegistryVersion"), positive=True)
        and _safe_nonnegative_integer(bundle.get("railRegistryVersion"), positive=True)
        and _non_boolean_number(bundle.get("finalisedAt"))
        and bundle["finalisedAt"] >= 0
    ):
        return False

    parties = bundle.get("parties")
    if not isinstance(parties, list) or len(parties) < 2:
        return False
    roles = set()
    claims = set()
    for party in parties:
        if not (
            isinstance(party, dict)
            and set(party) == {"role", "bundleHash", "primaryClaim"}
            and _string_member(party.get("role"), {"buyer", "seller", "orchestrator"})
            and _sha256_hex(party.get("bundleHash"))
            and _claim_reference_shape_valid(party.get("primaryClaim"))
            and party["role"] not in roles
            and party["primaryClaim"] not in claims
        ):
            return False
        roles.add(party["role"])
        claims.add(party["primaryClaim"])
    if not {"buyer", "seller"} <= roles:
        return False

    phase_summary = bundle.get("phaseSummary")
    if not isinstance(phase_summary, list):
        return False
    for entry in phase_summary:
        entry_required = {"index", "kind", "outcome"}
        entry_optional = {"errorClass", "retryExhausted", "txRefs", "attestationRef"}
        if not (
            isinstance(entry, dict)
            and entry_required <= set(entry) <= entry_required | entry_optional
            and _safe_nonnegative_integer(entry.get("index"))
            and _string_member(entry.get("kind"), SUPPORTED_PHASES)
            and _string_member(entry.get("outcome"), {"ok", "fail"})
            and (
                "errorClass" not in entry
                or _string_member(entry["errorClass"], {
                    "permanent", "transient", "counterparty", "substrate", "settlement-atomicity",
                })
            )
            and ("retryExhausted" not in entry or entry["retryExhausted"] is True)
            and (
                "txRefs" not in entry
                or isinstance(entry["txRefs"], list)
                and all(_chain_tx_ref_shape_valid(ref) for ref in entry["txRefs"])
            )
            and (
                "attestationRef" not in entry
                or _attestation_ref_shape_valid(entry["attestationRef"])
            )
        ):
            return False

    for field in ("vetRecords", "settlementEvidence", "amendments", "ratingRefs"):
        if field in bundle and (
            not isinstance(bundle[field], list)
            or any(not _attestation_ref_shape_valid(ref) for ref in bundle[field])
        ):
            return False
    if "agreementRef" in bundle and not _attestation_ref_shape_valid(bundle["agreementRef"]):
        return False
    if "cancellation" in bundle and not (
        isinstance(bundle["cancellation"], dict)
        and bundle["cancellation"] == {"claimedPolicy": "pre-commit"}
    ):
        return False

    signatures = bundle.get("signatures")
    return isinstance(signatures, list) and all(
        isinstance(signature, dict)
        and set(signature) == {"party", "algorithm", "value"}
        and _claim_reference_shape_valid(signature.get("party"))
        and signature.get("algorithm") == "ed25519"
        and _nonempty_jcs_string(signature.get("value"))
        for signature in signatures
    )


def _absolute_fault_bundle_shape_valid(bundle):
    kind = bundle_type(bundle)
    if kind == "finality-bound":
        return _finality_bound_fault_bundle_shape_valid(bundle)
    if kind not in {"fault", "evidence-bound"}:
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
    if pointer.get("faultBundleVersion") != "1" or "bundleVersion" in pointer:
        return {"ok": False, "reason": "not a FaultBundleExtendedPointer discriminator", "recomputedHash": None}
    recomputed = bundle_hash(dereferenced_bundle)
    if pointer["fullBundleContentHash"] != recomputed:
        return {"ok": False, "reason": "dereferenced content hash mismatch", "recomputedHash": recomputed}
    if binding is not None and binding.get("bundleContentHash") != recomputed:
        return {"ok": False, "reason": "binding.bundleContentHash != dereferenced hash", "recomputedHash": recomputed}
    return {"ok": True, "reason": "triple-identity holds", "recomputedHash": recomputed}


def _extended_pointer_url_shape_valid(pointer_kind, full_bundle_url):
    if not isinstance(full_bundle_url, str):
        return False
    if pointer_kind not in {"evidence-bound", "finality-bound"}:
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


def _resolve_absolute_fault_pointer_payload(
    pointer, dereferenced_bundle, binding, keys, ebfab_authority,
    finality_bound_authority, *, expected_jobid, expected_role,
    expected_signer, address_deriver,
):
    """Shared FAB/EBFAB/finality type, signature, authority, and identity checks.

    This is the historical verification core. Public current callers perform
    authenticated session/role/profile/JID admission before entering it; the
    explicitly named legacy wrapper uses it only for frozen archival fixtures.
    """
    if not isinstance(pointer, dict) or not isinstance(dereferenced_bundle, dict):
        return {"ok": False, "reason": "pointer and dereferenced bundle must be objects"}
    if binding is not None and not isinstance(binding, dict):
        return {"ok": False, "reason": "binding must be an object"}
    known_pointer_discriminators = {
        "bundleVersion",
        "faultBundleVersion",
        "evidenceBoundFaultBundleVersion",
        "finalityBoundEvidenceFaultBundleVersion",
    }
    if any(
        isinstance(key, str)
        and key.endswith("BundleVersion")
        and key not in known_pointer_discriminators
        for key in pointer
    ):
        return {"ok": False, "reason": "unknown pointer discriminator"}
    present_discriminators = {
        key for key in known_pointer_discriminators if key in pointer
    }
    if len(present_discriminators) != 1:
        return {"ok": False, "reason": "non-exclusive pointer discriminator"}
    only_discriminator = next(iter(present_discriminators))
    if only_discriminator == "bundleVersion" or pointer.get(only_discriminator) != "1":
        return {"ok": False, "reason": "unsupported pointer discriminator"}
    pointer_candidates = []
    if pointer.get("faultBundleVersion") == "1":
        pointer_candidates.append(("fault", FAULT_POINTER_DOMAIN))
    if pointer.get("evidenceBoundFaultBundleVersion") == "1":
        pointer_candidates.append(("evidence-bound", EVIDENCE_BOUND_FAULT_POINTER_DOMAIN))
    if pointer.get("finalityBoundEvidenceFaultBundleVersion") == "1":
        pointer_candidates.append(("finality-bound", FINALITY_BOUND_EVIDENCE_FAULT_POINTER_DOMAIN))
    if len(pointer_candidates) != 1:
        return {"ok": False, "reason": "unsupported or non-exclusive pointer discriminator"}
    pointer_kind, domain = pointer_candidates[0]
    if pointer_kind == "finality-bound":
        required = {
            "finalityBoundEvidenceFaultBundleVersion", "pointerKind", "fullBundleUrl",
            "fullBundleContentHash", "signature",
        }
        signature = pointer.get("signature")
        if not (
            required <= set(pointer) <= required | {"segmentRefs"}
            and isinstance(signature, dict)
            and set(signature) == {"signer", "algorithm", "value"}
            and _claim_reference_shape_valid(signature.get("signer"))
            and signature.get("algorithm") == "ed25519"
            and _nonempty_jcs_string(signature.get("value"))
        ):
            return {"ok": False, "reason": "malformed finality-bound pointer shape"}
    if bundle_type(dereferenced_bundle) != pointer_kind:
        return {"ok": False, "reason": "pointer and dereferenced bundle types differ"}
    if pointer.get("pointerKind") != "extended":
        return {"ok": False, "reason": "unsupported pointer kind"}
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
    if not _absolute_fault_bundle_shape_valid(dereferenced_bundle):
        return {"ok": False, "reason": "malformed dereferenced absolute-fault bundle"}
    bundle_ok, bundle_reason = _bundle_signatures_valid(dereferenced_bundle, keys)
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
            return {"ok": False, "reason": "EBFAB pointer lacks SEB validation authority"}
        seb_ok, seb_reason, _ = validate_ebfab(
            dereferenced_bundle,
            ebfab_authority.get("listing"),
            keys,
            ebfab_authority.get("referenceValidationByCanonicalRef"),
            ebfab_authority.get("bundleLifecycle"),
            ebfab_authority.get("sessionExecutionAuthorityByPhaseKey"),
            ebfab_authority.get("verifiedReceiptByCanonicalRef"),
            effective_pipeline=ebfab_authority.get("effectivePipeline"),
            additional_commit_phase=ebfab_authority.get("additionalCommitPhase"),
        )
        if not seb_ok:
            return {"ok": False, "reason": "dereferenced EBFAB fails SEB: " + seb_reason}
    elif pointer_kind == "finality-bound":
        if not isinstance(finality_bound_authority, dict):
            return {
                "ok": False,
                "decision": "indeterminate",
                "reason": "finality-bound pointer lacks verification authority",
            }
        decision, strong_reason, _ = validate_finality_bound_ebfab(
            dereferenced_bundle,
            finality_bound_authority.get("listing"),
            keys,
            finality_bound_authority.get("referenceValidationByCanonicalRef"),
            finality_bound_authority.get("bundleLifecycle"),
            finality_bound_authority.get("sessionExecutionAuthorityByPhaseKey"),
            finality_bound_authority.get("verifiedReceiptByCanonicalRef"),
            finality_bound_authority.get("finalityVerificationByCanonicalRef"),
            finality_bound_authority.get("finalityTrust"),
            effective_pipeline=finality_bound_authority.get("effectivePipeline"),
            additional_commit_phase=finality_bound_authority.get("additionalCommitPhase"),
        )
        if decision != "pass":
            return {
                "ok": False,
                "decision": decision,
                "reason": "dereferenced finality-bound bundle fails: " + strong_reason,
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
    return {"ok": True, "reason": "pointer type, signature, and triple identity hold"}


def resolve_absolute_fault_pointer(
    pointer, dereferenced_bundle, binding=None, pubkeys=None, ebfab_authority=None,
    trusted_contexts=None, *, finality_bound_authority=None,
    expected_jobid=None, expected_role=None,
):
    """Resolve a current absolute-fault pointer after verifier-owned admission.

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
    return _resolve_absolute_fault_pointer_payload(
        pointer,
        dereferenced_bundle,
        binding,
        keys,
        ebfab_authority,
        finality_bound_authority,
        expected_jobid=expected_jobid,
        expected_role=expected_role,
        expected_signer=expected_signer,
        address_deriver=_current_logical_address,
    )


def resolve_legacy_absolute_fault_pointer(
    pointer, dereferenced_bundle, binding=None, pubkeys=None, ebfab_authority=None,
    *, finality_bound_authority=None, expected_jobid=None, expected_role=None,
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
    return _resolve_absolute_fault_pointer_payload(
        pointer,
        dereferenced_bundle,
        binding,
        pubkeys,
        ebfab_authority,
        finality_bound_authority,
        expected_jobid=expected_jobid,
        expected_role=expected_role,
        expected_signer=None,
        address_deriver=legacy_logical_address,
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


def _derive(party, tagged_bundles, window_start, window_end, basis="finalisedAt", *, job_bound=False):
    """Executes the named §10.5.1 reputation-derivation predicates over selected fields; not a
    complete ReplayableReputationDerivation implementation.

    tagged_bundles: list of {"bundle": <dict>, "resolvedRole": "buyer"|"seller",
      "counterpartyDisposition": "present"|"absent"|None, "counterpartyRef": ...?,
      "absenceEvidenceRef": ...?, "selectedByRoleResolution": true?} — each input copy
      carries its §10.5.1 resolution tag. The job-bound variant additionally requires a
      trusted requested `resolvedJobId`. EBFAB inputs are admitted only by that variant and
      require the true marker because BB-6 resolution precedes SEB admission.

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
        # member and no EBFAB admission. Keep this path byte-compatible with released v1.
        scoped = [t for t in tagged_bundles
                  if isinstance(t, dict)
                  and bundle_type(t.get("bundle")) in {"legacy", "fault"}
                  and party in _primary_claims(t["bundle"])
                  and window_start <= t["bundle"][clock] <= window_end]
    else:
        candidates = []
        rejected_selected_jobs = set()
        for tagged in tagged_bundles:
            if not isinstance(tagged, dict):
                continue
            bundle = tagged.get("bundle")
            kind = bundle_type(bundle)
            selected = tagged.get("selectedByRoleResolution") is True

            # The requested jobId belongs to authenticated address/binding resolution
            # context. Never recover it from returned bundle content.
            if kind in {"evidence-bound", "finality-bound"} and not selected:
                continue
            resolved_job = tagged.get("resolvedJobId")
            if not isinstance(resolved_job, str) or not resolved_job:
                if kind is None and not selected:
                    continue
                raise ValueError("admitted role resolution lacks trusted resolvedJobId")
            if kind is None and not selected:
                continue
            if kind is None:
                rejected_selected_jobs.add(resolved_job)
                continue
            if bundle.get("jobId") != resolved_job:
                rejected_selected_jobs.add(resolved_job)
                continue
            if kind in {"evidence-bound", "finality-bound"} and not _tagged_copy_valid_for_derive(tagged):
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


def derive_job_bound(party, tagged_bundles, window_start, window_end, basis="finalisedAt"):
    """Emit the distinct job-bound replay receipt used by strengthened EBFAB replay."""
    return _derive(party, tagged_bundles, window_start, window_end, basis, job_bound=True)


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
        ok_w, reason_w = _bundle_shape_ok(auth)
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
            ok_cp, reason_cp = _bundle_shape_ok(cp)
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
                pf_cp_ok, pf_cp_reason = _post_fetch_valid(cp, cp_binding, pubkeys)
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
    )


def _replay_receipt(derivation, deref, party, window_start, window_end,
                    evidence_deref=None, pubkeys=None, anchor_deref=None,
                    pure_mapping_resolver=None, ebfab_authority_resolver=None,
                    *, binding_verifier, address_validator,
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
        entry_authorities=entry_authorities)
    if not ok:
        return (False, None)
    tagged = []
    for entry in derivation["resolutionContext"]:
        b = _deref_role_copy(anchor_deref, entry["roleEvidence"])
        if bundle_type(b) == "finality-bound":
            # No existing receipt discriminator claims the coordinated #391+#392
            # contract. Refuse instead of silently dropping the stronger copy.
            return (False, None)
        tag = {"bundle": b, "resolvedRole": entry["resolvedRole"],
               "counterpartyDisposition": entry.get("counterpartyDisposition"),
               "counterpartyRef": entry.get("counterpartyRef"),
               "counterpartyRoleEvidence": entry.get("counterpartyRoleEvidence"),
               "absenceEvidenceRef": entry.get("absenceEvidenceRef"),
               "absenceBinding": entry.get("absenceBinding"),
               "roleEvidence": entry.get("roleEvidence"),
               "bb6Context": entry.get("bb6Context")}
        if job_bound:
            tag["resolvedJobId"] = entry["resolvedJobId"]
            tag["selectedByRoleResolution"] = True
            if bundle_type(b) == "evidence-bound":
                authority = (
                    ebfab_authority_resolver(b, entry)
                    if callable(ebfab_authority_resolver)
                    else None
                )
                if not isinstance(authority, dict):
                    return (False, None)
                tag["ebfabAuthority"] = authority
                if not _tagged_copy_valid_for_derive(tag):
                    return (False, None)
        tagged.append(tag)
        if job_bound and entry.get("counterpartyDisposition") == "present":
            counterparty = _deref_role_copy(
                anchor_deref, entry.get("counterpartyRoleEvidence")
            )
            if bundle_type(counterparty) == "finality-bound":
                return (False, None)
            if bundle_type(counterparty) == "evidence-bound":
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
                    "ebfabAuthority": authority,
                }
                if not _tagged_copy_valid_for_derive(counterparty_tag):
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
    replayed = (derive_job_bound if job_bound else derive)(
        party, tagged, window_start, window_end, basis)
    same = (canonical(replayed["metrics"]) == canonical(derivation["metrics"])
            and replayed["bundleCount"] == derivation["bundleCount"])
    return (same, replayed)


# --------------------------------------------------------------------------- #
# Coordinated #391 + #392 current-use replayable reputation consumer
# --------------------------------------------------------------------------- #

CURRENT_USE_REPLAYABLE_DERIVATION_VERSION = "1"
_ALL_DERIVATION_DISCRIMINATORS = frozenset({
    "derivationVersion",
    "replayableDerivationVersion",
    "jobBoundReplayableDerivationVersion",
    "settlementVerifiedDerivationVersion",
    "replayableSettlementVerifiedDerivationVersion",
    "currentUseReplayableDerivationVersion",
})
_CURRENT_USE_PAYMENT_BINDING_REQUIRED = frozenset({"pay-ap2", "pay-x402"})
_SYNTHETIC_PURE_MAPPING_PROFILE = "dacs-current-use-synthetic-pure-mapping-v1"


def _current_use_result(decision, reason, derivation=None):
    return {"decision": decision, "reason": reason, "derivation": derivation}


def _jcs_hash(value, omitted=()):
    omitted = {omitted} if isinstance(omitted, str) else set(omitted)
    return hashlib.sha256(_new_type_canonical({
        key: item for key, item in value.items() if key not in omitted
    })).hexdigest()


def legacy_checkpoint_hash(checkpoint):
    return _jcs_hash(checkpoint, "signature")


def legacy_checkpoint_binding_hash(binding):
    return _jcs_hash(binding, "signature")


def current_use_synthetic_proof_hash(proof):
    return _jcs_hash(proof, "signature")


def legacy_checkpoint_logical_address(substrate):
    if not _nonempty_jcs_string(substrate):
        raise ValueError("checkpoint substrate must be a non-empty JCS string")
    return "dacs5:legacy-bundle-checkpoint:v1:" + quote(substrate, safe="-._~")


def require_current_use_replayable_derivation(derivation):
    """Exclusive discriminator gate for the combined stronger consumer.

    This gate is intentionally independent of the existing replay dispatch.  Old
    replay consumers continue to reject the new discriminator as unknown, while a
    caller requesting this stronger contract cannot satisfy it by stripping or
    relabelling the object as an older derivation.
    """
    if not isinstance(derivation, dict):
        return {"ok": False, "reason": "current-use derivation is not an object"}
    present = {
        key for key in derivation
        if isinstance(key, str) and key.endswith("DerivationVersion")
    }
    unknown = present - _ALL_DERIVATION_DISCRIMINATORS
    if unknown:
        return {"ok": False, "reason": "unknown derivation discriminator: "
                + ", ".join(sorted(unknown))}
    if present != {"currentUseReplayableDerivationVersion"}:
        return {"ok": False, "reason": "current-use derivation discriminator is missing or non-exclusive"}
    if derivation.get("currentUseReplayableDerivationVersion") != CURRENT_USE_REPLAYABLE_DERIVATION_VERSION:
        return {"ok": False, "reason": "unsupported currentUseReplayableDerivationVersion"}
    return {"ok": True, "reason": "current-use discriminator holds"}


def _configured_party_maps(verifier_config, job_id):
    role_maps = verifier_config.get("partyRolesByJob") if isinstance(verifier_config, dict) else None
    role_map = role_maps.get(job_id) if isinstance(role_maps, dict) else None
    if not isinstance(role_map, dict) or set(role_map) != {"buyer", "seller"}:
        return (None, None)
    if not all(_nonempty_jcs_string(role_map.get(role)) for role in ("buyer", "seller")):
        return (None, None)
    if role_map["buyer"] == role_map["seller"]:
        return (None, None)
    return (role_map, {signer: role for role, signer in role_map.items()})


def _current_use_roster_matches_role_map(bundle, role_map):
    """Bind every authenticated buyer/seller roster copy to verifier authority."""
    parties = bundle.get("parties") if isinstance(bundle, dict) else None
    if not isinstance(parties, list) or not isinstance(role_map, dict):
        return False
    expected_by_claim = {role_map.get(role): role for role in ("buyer", "seller")}
    observed = {"buyer": [], "seller": []}
    for party in parties:
        if not isinstance(party, dict):
            return False
        role = party.get("role")
        claim = party.get("primaryClaim")
        if role in observed:
            observed[role].append(claim)
        if claim in expected_by_claim and role != expected_by_claim[claim]:
            return False
    return all(observed[role] == [role_map[role]] for role in ("buyer", "seller"))


def _proof_signature_valid(proof, domain, keys, authorized_signer):
    signature = proof.get("signature") if isinstance(proof, dict) else None
    if (
        not isinstance(signature, dict)
        or set(signature) != {"signer", "algorithm", "value"}
        or signature.get("signer") != authorized_signer
        or signature.get("algorithm") != "ed25519"
        or not isinstance(keys, dict)
        or authorized_signer not in keys
    ):
        return False
    canonical_ok, _ = sig6_canonical(signature.get("value"))
    return bool(
        canonical_ok
        and verify_sig(
            keys[authorized_signer], domain,
            current_use_synthetic_proof_hash(proof), signature["value"])
    )


def _verify_synthetic_anchor_proof(proof, verifier_config):
    """Verify the explicitly synthetic offline native-order proof.

    Production consumers replace this bounded codec with their substrate's real
    receipt/finality verifier.  Trust keys and authorized signers come only from
    verifier configuration, never from the proof under test.
    """
    required = {
        "syntheticAnchorProofVersion", "purpose", "substrate", "subjectId", "subjectRole",
        "logicalAddress", "nativeAddress", "contentHash", "transactionRef",
        "writer", "nonce", "position", "state", "observationDisposition", "signature",
    }
    if not isinstance(proof, dict) or set(proof) != required:
        return ("error", "synthetic native anchor proof is malformed")
    position = proof.get("position")
    if (
        proof.get("syntheticAnchorProofVersion") != "1"
        or not _string_member(proof.get("purpose"), {"checkpoint", "historical-bundle", "current-bundle"})
        or not all(_nonempty_jcs_string(proof.get(field)) for field in (
            "substrate", "subjectId", "subjectRole", "logicalAddress", "nativeAddress",
            "transactionRef", "writer",
        ))
        or not _sha256_hex(proof.get("contentHash"))
        or not _safe_nonnegative_integer(proof.get("nonce"))
        or not isinstance(position, dict)
        or set(position) != {"orderDomain", "height", "index"}
        or not _nonempty_jcs_string(position.get("orderDomain"))
        or not _safe_nonnegative_integer(position.get("height"))
        or not _safe_nonnegative_integer(position.get("index"))
        or not _string_member(proof.get("state"), {"included", "finalized"})
        or not _string_member(proof.get("observationDisposition"), {
            "established", "pruned", "reorganized", "unorderable",
        })
    ):
        return ("error", "synthetic native anchor proof has an invalid closed shape")
    authority_by_substrate = verifier_config.get("nativeAuthorityBySubstrate")
    signer = (
        authority_by_substrate.get(proof["substrate"])
        if isinstance(authority_by_substrate, dict) else None
    )
    if not _nonempty_jcs_string(signer):
        return ("indeterminate", "native observation authority is unavailable")
    if not _proof_signature_valid(
        proof,
        CURRENT_USE_SYNTHETIC_ANCHOR_PROOF_DOMAIN,
        verifier_config.get("nativeAuthorityKeys"),
        signer,
    ):
        return ("fail", "synthetic native anchor proof signature does not verify")
    pinned = verifier_config.get("pinnedSyntheticAnchorProofHashBySubject")
    pin_key = ":".join((
        proof["substrate"], proof["purpose"], proof["subjectId"],
        proof["subjectRole"], proof["nativeAddress"],
    ))
    if not isinstance(pinned, dict) or pin_key not in pinned:
        return ("indeterminate", "independently pinned native observation is unavailable")
    if pinned[pin_key] != current_use_synthetic_proof_hash(proof):
        return ("fail", "synthetic native anchor proof differs from verifier-pinned observation")
    if proof["observationDisposition"] != "established" or proof["state"] != "finalized":
        return ("indeterminate", "native anchor history is pruned, reorganized, unorderable, or non-final")
    return ("pass", "synthetic finalized native anchor proof verified")


def _checkpoint_shape_valid(checkpoint):
    required = {
        "legacyBundleCheckpointVersion", "substrate", "policy", "createdAt", "signature",
    }
    return (
        isinstance(checkpoint, dict)
        and set(checkpoint) == required
        and checkpoint.get("legacyBundleCheckpointVersion") == "1"
        and _nonempty_jcs_string(checkpoint.get("substrate"))
        and checkpoint.get("policy") == "legacy-attestation-pre-checkpoint-only"
        and _non_boolean_number(checkpoint.get("createdAt"))
        and isinstance(checkpoint.get("signature"), dict)
    )


def _checkpoint_signature_valid(checkpoint, signer, public_keys):
    signature = checkpoint.get("signature") if isinstance(checkpoint, dict) else None
    if (
        not isinstance(signature, dict)
        or set(signature) != {"signer", "algorithm", "value"}
        or signature.get("signer") != signer
        or signature.get("algorithm") != "ed25519"
        or not isinstance(public_keys, dict)
        or signer not in public_keys
    ):
        return False
    canonical_ok, _ = sig6_canonical(signature.get("value"))
    return bool(canonical_ok and verify_sig(
        public_keys[signer], LEGACY_BUNDLE_CHECKPOINT_DOMAIN,
        legacy_checkpoint_hash(checkpoint), signature["value"]))


def _checkpoint_binding_valid(binding, substrate, signer, public_keys):
    required = {
        "legacyBundleCheckpointBindingVersion", "substrate", "logicalAddress",
        "nativeAddress", "checkpointContentHash", "anchorTx", "signer", "signature",
    }
    if (
        not isinstance(binding, dict)
        or set(binding) != required
        or binding.get("legacyBundleCheckpointBindingVersion") != "1"
        or binding.get("substrate") != substrate
        or binding.get("logicalAddress") != legacy_checkpoint_logical_address(substrate)
        or not all(_nonempty_jcs_string(binding.get(field)) for field in (
            "nativeAddress", "anchorTx", "signer",
        ))
        or not _sha256_hex(binding.get("checkpointContentHash"))
        or binding.get("signer") != signer
    ):
        return False
    signature = binding.get("signature")
    if (
        not isinstance(signature, dict)
        or set(signature) != {"signer", "algorithm", "value"}
        or signature.get("signer") != signer
        or signature.get("algorithm") != "ed25519"
        or not isinstance(public_keys, dict)
        or signer not in public_keys
    ):
        return False
    canonical_ok, _ = sig6_canonical(signature.get("value"))
    return bool(canonical_ok and verify_sig(
        public_keys[signer], LEGACY_BUNDLE_CHECKPOINT_BINDING_DOMAIN,
        legacy_checkpoint_binding_hash(binding), signature["value"]))


def _pure_native_address(substrate, logical, verifier_config):
    profiles = verifier_config.get("pureMappingProfileBySubstrate")
    profile = profiles.get(substrate) if isinstance(profiles, dict) else None
    if profile != _SYNTHETIC_PURE_MAPPING_PROFILE:
        return None
    return "pure-" + hashlib.sha256(logical.encode("utf-8")).hexdigest()


def _strictly_before(left, right):
    left_position = left.get("position") if isinstance(left, dict) else None
    right_position = right.get("position") if isinstance(right, dict) else None
    if not isinstance(left_position, dict) or not isinstance(right_position, dict):
        return None
    if left_position.get("orderDomain") != right_position.get("orderDomain"):
        return None
    return (left_position["height"], left_position["index"]) < (
        right_position["height"], right_position["index"])


def _lookup_by_address(dependencies, collection, address):
    values = dependencies.get(collection) if isinstance(dependencies, dict) else None
    return values.get(address) if isinstance(values, dict) else None


def _selection_context_shape(context):
    return (
        isinstance(context, dict)
        and set(context) == {"candidateBindings", "partyMap", "budget"}
        and isinstance(context.get("candidateBindings"), list)
        and isinstance(context.get("partyMap"), dict)
        and isinstance(context.get("budget"), int)
        and not isinstance(context.get("budget"), bool)
        and context["budget"] >= 1
    )


def _verify_original_binding_mapping(
    bundle, evidence, original, historical_receipt, dependencies, verifier_config,
    role_map, signer_map,
):
    if not isinstance(original, dict) or set(original) != {
        "kind", "binding", "selectionContext", "anchorTransaction", "writer", "nonce",
    }:
        return ("error", "historical original BundleBinding mapping is malformed")
    binding = original.get("binding")
    context = original.get("selectionContext")
    role = evidence["resolvedRole"]
    job_id = evidence["resolvedJobId"]
    public_keys = verifier_config.get("publicKeys")
    if not _selection_context_shape(context):
        return ("error", "historical original BB-6 selection context is malformed")
    if context["partyMap"] != signer_map:
        return ("fail", "historical original party map is not verifier-authenticated")
    expected_budget = verifier_config.get("bb6Budget", BB6_DEFAULT_BUDGET)
    if context["budget"] != expected_budget:
        return ("fail", "historical original BB-6 budget differs from verifier policy")
    selected = verify_legacy_binding(
        binding, public_keys, expected_jobid=job_id, expected_role=role,
        expected_content_hash=evidence["bundleContentHash"])
    if not selected["ok"] or binding.get("signer") != role_map[role]:
        return ("fail", "historical original BundleBinding is not the authenticated role-holder binding")

    # Original BB-6 reconstruction uses the independently pinned party map.  Outsider
    # junk is pruned before shape/signature work; an authorized malformed candidate
    # remains a deterministic failure.
    survivors = [candidate for candidate in context["candidateBindings"]
                 if isinstance(candidate, dict)
                 and context["partyMap"].get(candidate.get("signer")) == role]
    anchored = {}
    valid = []
    for candidate in survivors:
        checked = verify_legacy_binding(
            candidate, public_keys, expected_jobid=job_id, expected_role=role)
        if not checked["ok"]:
            return ("fail", "authorized historical BB-6 candidate does not verify")
        fetched = _lookup_by_address(dependencies, "bundlesByNativeAddress", candidate["nativeAddress"])
        if not isinstance(fetched, dict):
            return ("indeterminate", "historical BB-6 candidate cannot be dereferenced")
        shape_ok, _ = _bundle_shape_ok(fetched)
        if not shape_ok:
            continue
        post_ok, _ = _post_fetch_valid(fetched, candidate, public_keys)
        if not post_ok:
            continue
        anchored[candidate["nativeAddress"]] = fetched
        valid.append(candidate)
    resolution = resolve_bb6(valid, context["partyMap"], context["budget"], anchored)
    if (
        resolution["disposition"] != "present"
        or resolution["resolvedNativeAddress"] != binding.get("nativeAddress")
    ):
        return ("indeterminate", "historical original BB-6 selection is not reproducible")
    original_bundle = anchored.get(binding["nativeAddress"])
    if not isinstance(original_bundle, dict) or bundle_hash(original_bundle) != bundle_hash(bundle):
        return ("fail", "historical original mapping resolves different bundle bytes")
    if not (
        historical_receipt.get("logicalAddress") == binding.get("logicalAddress")
        and historical_receipt.get("nativeAddress") == binding.get("nativeAddress")
        and historical_receipt.get("contentHash") == binding.get("bundleContentHash")
        and historical_receipt.get("writer") == binding.get("signer") == role_map[role]
        and historical_receipt.get("transactionRef") == original.get("anchorTransaction")
        and historical_receipt.get("writer") == original.get("writer")
        and historical_receipt.get("nonce") == original.get("nonce")
    ):
        return ("fail", "historical receipt does not join the original BundleBinding tuple")
    return ("pass", "historical original BundleBinding and BB-6 selection verified")


def _verify_original_pure_mapping(
    bundle, evidence, original, historical_receipt, dependencies, verifier_config,
    role_map,
):
    if not isinstance(original, dict) or set(original) != {
        "kind", "logicalAddress", "nativeAddress", "anchorTransaction", "writer", "nonce",
    }:
        return ("error", "historical original pure-mapping proof is malformed")
    job_id = evidence["resolvedJobId"]
    role = evidence["resolvedRole"]
    logical = legacy_logical_address(job_id, role)
    expected_native = _pure_native_address(evidence["substrate"], logical, verifier_config)
    if expected_native is None:
        return ("indeterminate", "pure-mapping verifier is unavailable")
    if original.get("logicalAddress") != logical or original.get("nativeAddress") != expected_native:
        return ("fail", "historical pure mapping does not derive the exact role address")
    original_bundle = _lookup_by_address(dependencies, "bundlesByNativeAddress", expected_native)
    if not isinstance(original_bundle, dict):
        return ("indeterminate", "historical pure-mapped bundle cannot be dereferenced")
    post_ok, _ = _post_fetch_legacy_address_valid(
        original_bundle, expected_native, role, evidence["bundleContentHash"],
        verifier_config.get("publicKeys"), expected_jobid=job_id,
        pure_mapping_resolver=lambda _job, _role: expected_native)
    if not post_ok or bundle_hash(original_bundle) != bundle_hash(bundle):
        return ("fail", "historical pure-mapping proof resolves different or invalid bytes")
    if not (
        historical_receipt.get("logicalAddress") == logical
        and historical_receipt.get("nativeAddress") == expected_native
        and historical_receipt.get("contentHash") == evidence["bundleContentHash"]
        and historical_receipt.get("writer") == role_map[role]
        and historical_receipt.get("transactionRef") == original.get("anchorTransaction")
        and historical_receipt.get("writer") == original.get("writer")
        and historical_receipt.get("nonce") == original.get("nonce")
    ):
        return ("fail", "historical receipt does not join the pure-mapping tuple")
    return ("pass", "historical original pure mapping verified")


def validate_legacy_bundle_admission(bundle, evidence, dependencies, verifier_config):
    """Authenticate one legacy copy's original role mapping and pre-checkpoint order."""
    try:
        if bundle_type(bundle) != "legacy":
            return ("error", "legacy admission requires an AttestationBundle")
        if evidence is None:
            return ("indeterminate", "legacy era evidence is unavailable")
        required = {
            "bundleContentHash", "resolvedJobId", "resolvedRole", "substrate",
            "checkpointCandidates", "checkpointReceipt", "historicalAnchorReceipt",
            "originalMapping",
        }
        if not isinstance(evidence, dict) or set(evidence) != required:
            return ("error", "legacy era evidence is malformed")
        job_id = evidence.get("resolvedJobId")
        role = evidence.get("resolvedRole")
        substrate = evidence.get("substrate")
        if (
            not _nonempty_jcs_string(job_id)
            or not _string_member(role, {"buyer", "seller"})
            or not _nonempty_jcs_string(substrate)
            or evidence.get("bundleContentHash") != bundle_hash(bundle)
            or bundle.get("jobId") != job_id
            or bundle.get("anchoredByRole") != role
        ):
            return ("fail", "legacy era evidence does not bind the exact job, role, and content hash")
        role_map, signer_map = _configured_party_maps(verifier_config, job_id)
        if role_map is None:
            return ("indeterminate", "historical party authority is unavailable")
        candidates = evidence.get("checkpointCandidates")
        if not isinstance(candidates, list):
            return ("error", "checkpoint discovery candidates are not an array")
        steward_map = verifier_config.get("authorizedStewardBySubstrate")
        steward = steward_map.get(substrate) if isinstance(steward_map, dict) else None
        public_keys = verifier_config.get("publicKeys")
        if not _nonempty_jcs_string(steward):
            return ("indeterminate", "checkpoint steward authority is unavailable")

        checkpoint_receipt = evidence.get("checkpointReceipt")
        checkpoint_decision, checkpoint_reason = _verify_synthetic_anchor_proof(
            checkpoint_receipt, verifier_config)
        if checkpoint_decision != "pass":
            return (checkpoint_decision, checkpoint_reason)
        pure_checkpoint_native = _pure_native_address(
            substrate, legacy_checkpoint_logical_address(substrate), verifier_config)
        if pure_checkpoint_native is not None:
            if candidates:
                return ("error", "pure-mapping checkpoint evidence must not carry write-input bindings")
            checkpoint_binding = {
                "logicalAddress": legacy_checkpoint_logical_address(substrate),
                "nativeAddress": pure_checkpoint_native,
                "checkpointContentHash": checkpoint_receipt.get("contentHash"),
                "anchorTx": checkpoint_receipt.get("transactionRef"),
                "signer": steward,
            }
        else:
            # Authenticate, discard, and deduplicate before multiplicity.  Candidate-
            # supplied authority flags or steward lists are never consulted.
            survivors = {}
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                if not _checkpoint_binding_valid(candidate, substrate, steward, public_keys):
                    continue
                identity = legacy_checkpoint_binding_hash(candidate)
                survivors.setdefault(identity, candidate)
            if not survivors:
                return ("indeterminate", "no authorized checkpoint discovery candidate survives")
            if len(survivors) != 1:
                return ("indeterminate", "conflicting authorized checkpoint discovery candidates survive")
            checkpoint_binding = next(iter(survivors.values()))
        checkpoint = _lookup_by_address(
            dependencies, "checkpointsByNativeAddress", checkpoint_binding["nativeAddress"])
        if not isinstance(checkpoint, dict):
            return ("indeterminate", "checkpoint artifact cannot be dereferenced")
        if (
            not _checkpoint_shape_valid(checkpoint)
            or checkpoint.get("substrate") != substrate
            or legacy_checkpoint_hash(checkpoint) != checkpoint_binding["checkpointContentHash"]
            or not _checkpoint_signature_valid(checkpoint, steward, public_keys)
        ):
            return ("fail", "resolved checkpoint shape, hash, or steward signature is invalid")
        if not (
            checkpoint_receipt.get("purpose") == "checkpoint"
            and checkpoint_receipt.get("substrate") == substrate
            and checkpoint_receipt.get("subjectId") == substrate
            and checkpoint_receipt.get("subjectRole") == "steward"
            and checkpoint_receipt.get("logicalAddress") == checkpoint_binding["logicalAddress"]
            and checkpoint_receipt.get("nativeAddress") == checkpoint_binding["nativeAddress"]
            and checkpoint_receipt.get("contentHash") == checkpoint_binding["checkpointContentHash"]
            and checkpoint_receipt.get("transactionRef") == checkpoint_binding["anchorTx"]
            and checkpoint_receipt.get("writer") == checkpoint_binding["signer"] == steward
        ):
            return ("fail", "checkpoint receipt does not join binding, artifact, transaction, and writer")

        historical_receipt = evidence.get("historicalAnchorReceipt")
        historical_decision, historical_reason = _verify_synthetic_anchor_proof(
            historical_receipt, verifier_config)
        if historical_decision != "pass":
            return (historical_decision, historical_reason)
        if not (
            historical_receipt.get("purpose") == "historical-bundle"
            and historical_receipt.get("substrate") == substrate
            and historical_receipt.get("subjectId") == job_id
            and historical_receipt.get("subjectRole") == role
            and historical_receipt.get("contentHash") == evidence["bundleContentHash"]
        ):
            return ("fail", "historical receipt does not join the exact job, role, and content hash")
        ordering = _strictly_before(historical_receipt, checkpoint_receipt)
        if ordering is None:
            return ("indeterminate", "historical and checkpoint receipts are not comparably ordered")
        if not ordering:
            return ("fail", "legacy bundle anchor is not strictly before the checkpoint")

        original = evidence.get("originalMapping")
        if isinstance(original, dict) and original.get("kind") == "binding":
            return _verify_original_binding_mapping(
                bundle, evidence, original, historical_receipt, dependencies,
                verifier_config, role_map, signer_map)
        if isinstance(original, dict) and original.get("kind") == "pure":
            return _verify_original_pure_mapping(
                bundle, evidence, original, historical_receipt, dependencies,
                verifier_config, role_map)
        return ("error", "historical original mapping kind is unsupported")
    except (KeyError, TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        return ("error", "legacy era evidence is malformed")


def _settlement_binding_proof_decision(proof, record, phase_index, verifier_config):
    required = {
        "syntheticSettlementBindingProofVersion", "jobId", "phaseIndex", "phase",
        "paymentTxRefsHash", "state", "observedAt", "signature",
    }
    if not isinstance(proof, dict) or set(proof) != required:
        return ("error", "required settlement binding proof is malformed")
    if (
        proof.get("syntheticSettlementBindingProofVersion") != "1"
        or proof.get("jobId") != record.get("jobId")
        or proof.get("phaseIndex") != phase_index
        or proof.get("phase") != record.get("phase")
        or proof.get("paymentTxRefsHash") != _jcs_hash({"paymentTxRefs": record.get("paymentTxRefs")})
        or not _non_boolean_number(proof.get("observedAt"))
        or not _string_member(proof.get("state"), {
            "match", "mismatch", "absent", "unavailable", "pruned", "reorganized",
        })
    ):
        return ("error", "required settlement binding proof has an invalid closed shape")
    authority_map = verifier_config.get("settlementBindingAuthorityByPhase")
    signer = authority_map.get(record.get("phase")) if isinstance(authority_map, dict) else None
    if not _nonempty_jcs_string(signer):
        return ("indeterminate", "required settlement binding authority is unavailable")
    if not _proof_signature_valid(
        proof,
        CURRENT_USE_SYNTHETIC_SETTLEMENT_BINDING_PROOF_DOMAIN,
        verifier_config.get("settlementBindingAuthorityKeys"), signer,
    ):
        return ("fail", "required settlement binding proof signature does not verify")
    if proof["state"] == "match":
        return ("pass", "required settlement-side job binding verified")
    if proof["state"] == "mismatch":
        return ("fail", "required settlement-side job binding mismatches")
    return ("indeterminate", "required settlement-side job binding is unavailable; no unbound fallback")


def _authority_for_bundle(bundle, dependencies):
    authorities = dependencies.get("bundleAuthorityByContentHash") if isinstance(dependencies, dict) else None
    return authorities.get(bundle_hash(bundle)) if isinstance(authorities, dict) else None


def _validate_current_use_type_authority(bundle, dependencies, verifier_config):
    """Run all type-specific authority and current successful-payment gates."""
    kind = bundle_type(bundle)
    public_keys = verifier_config.get("publicKeys")
    if kind is None:
        return ("error", "bundle discriminator is missing, unknown, or non-exclusive", None)
    try:
        shape_ok = (
            _absolute_fault_bundle_shape_valid(bundle)
            if kind in {"fault", "evidence-bound", "finality-bound"}
            else _bundle_shape_ok(bundle)[0]
        )
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError):
        shape_ok = False
    if not shape_ok:
        return ("error", "bundle has a malformed closed shape", None)
    signature_ok, signature_reason = _bundle_signatures_valid(bundle, public_keys)
    if not signature_ok:
        return ("fail", signature_reason, None)
    authority = _authority_for_bundle(bundle, dependencies)
    if kind == "evidence-bound":
        if not isinstance(authority, dict):
            return ("indeterminate", "EBFAB authority is unavailable", None)
        ok, reason, _ = validate_ebfab(
            bundle, authority.get("listing"), public_keys,
            authority.get("referenceValidationByCanonicalRef"),
            authority.get("bundleLifecycle"),
            authority.get("sessionExecutionAuthorityByPhaseKey"),
            authority.get("verifiedReceiptByCanonicalRef"),
            effective_pipeline=authority.get("effectivePipeline"),
            additional_commit_phase=authority.get("additionalCommitPhase"))
        if not ok:
            return ("fail", reason, None)
        return ("pass", "EBFAB authority verified", {
            "records": [], "successfulPayments": [], "finalityClasses": [],
        })
    if kind != "finality-bound":
        return ("pass", "older bundle type and signatures verified", {
            "records": [], "successfulPayments": [], "finalityClasses": [],
        })
    if not isinstance(authority, dict):
        return ("indeterminate", "finality-bound bundle authority is unavailable", None)
    finality_trust = verifier_config.get("finalityTrust")
    decision, reason, phase_keys = validate_finality_bound_ebfab(
        bundle, authority.get("listing"), public_keys,
        authority.get("referenceValidationByCanonicalRef"),
        authority.get("bundleLifecycle"),
        authority.get("sessionExecutionAuthorityByPhaseKey"),
        authority.get("verifiedReceiptByCanonicalRef"),
        authority.get("finalityVerificationByCanonicalRef"), finality_trust,
        effective_pipeline=authority.get("effectivePipeline"),
        additional_commit_phase=authority.get("additionalCommitPhase"))
    if decision != "pass":
        return (decision, reason, None)

    records = []
    successful_payments = []
    classes = []
    references = bundle.get("settlementEvidence", [])
    for ref in references:
        key = canonical(ref).decode("utf-8")
        resolution = authority["referenceValidationByCanonicalRef"].get(key)
        record = resolution.get("record") if isinstance(resolution, dict) else None
        if not isinstance(record, dict):
            return ("indeterminate", "RSV record authority is unavailable", None)
        records.append(record)
        if record.get("phase") not in PAYMENT_PHASES or record.get("outcome") != "success":
            continue
        candidate = authority["finalityVerificationByCanonicalRef"].get(key)
        if not isinstance(candidate, dict) or candidate.get("evidence") != record:
            return ("indeterminate", "successful payment finality input is unavailable", None)
        exact_finality = verify_finality(candidate, finality_trust)
        if exact_finality.get("decision") != "pass":
            return (exact_finality.get("decision", "error"), exact_finality.get("reason", "FV failed"), None)
        classes.append(exact_finality["finalityClass"])
        phase_entry = next((
            entry for entry in bundle.get("phaseSummary", [])
            if isinstance(entry, dict)
            and entry.get("kind") == record.get("phase")
            and canonical(entry.get("attestationRef")) == canonical(ref)
        ), None)
        if not isinstance(phase_entry, dict) or not _safe_nonnegative_integer(phase_entry.get("index")):
            return ("fail", "successful payment lacks authenticated phase-index binding", None)
        successful_payments.append({
            "record": record,
            "phaseIndex": phase_entry["index"],
            "evidenceHash": settlement_evidence_hash(record),
        })
        if record.get("phase") in _CURRENT_USE_PAYMENT_BINDING_REQUIRED:
            proof_map = dependencies.get("settlementBindingProofByCanonicalRef")
            proof = proof_map.get(key) if isinstance(proof_map, dict) else None
            if proof is None:
                return ("indeterminate", "required settlement binding proof is unavailable; no unbound fallback", None)
            phase_key = str(phase_entry["index"]) + ":" + record["phase"]
            if phase_key not in phase_keys:
                phase_key = None
            if phase_key is None:
                return ("fail", "successful payment lacks authenticated phase-index binding", None)
            binding_decision, binding_reason = _settlement_binding_proof_decision(
                proof, record, int(phase_key.split(":", 1)[0]), verifier_config)
            if binding_decision != "pass":
                return (binding_decision, binding_reason, None)
    return ("pass", "finality, RSV, and applicable SB-3 checks passed", {
        "records": records,
        "successfulPayments": successful_payments,
        "finalityClasses": classes,
    })


def _current_anchor_join(receipt, binding, bundle, substrate, verifier_config):
    decision, reason = _verify_synthetic_anchor_proof(receipt, verifier_config)
    if decision != "pass":
        return (decision, reason)
    if not (
        receipt.get("purpose") == "current-bundle"
        and receipt.get("substrate") == substrate
        and receipt.get("subjectId") == binding.get("jobId")
        and receipt.get("subjectRole") == binding.get("role")
        and receipt.get("logicalAddress") == binding.get("logicalAddress")
        and receipt.get("nativeAddress") == binding.get("nativeAddress")
        and receipt.get("contentHash") == binding.get("bundleContentHash") == bundle_hash(bundle)
        and receipt.get("writer") == binding.get("signer")
    ):
        return ("fail", "current anchor receipt does not join binding, role, bytes, and writer")
    return ("pass", "current anchor receipt verified")


def _validate_current_use_absence(
    job_id, role, substrate, dependencies, verifier_config, role_map,
    current_key_authority, trusted_context,
):
    configured = verifier_config.get("authenticatedAbsenceByJobRole")
    authority = configured.get(job_id + ":" + role) if isinstance(configured, dict) else None
    if not isinstance(authority, dict) or set(authority) != {
        "disposition", "absenceEvidenceRef", "absenceBinding",
    }:
        return ("indeterminate", "role absence is not authenticated", None)
    if authority.get("disposition") != "absent":
        return ("indeterminate", "role absence authority is not established", None)
    ref = authority.get("absenceEvidenceRef")
    if (
        not isinstance(ref, dict)
        or set(ref) != {"kind", "locator", "contentHash"}
        or not all(_nonempty_jcs_string(ref.get(field)) for field in ("kind", "locator"))
        or not _sha256_hex(ref.get("contentHash"))
    ):
        return ("error", "absence evidence reference is malformed", None)
    evidence_by_ref = dependencies.get("absenceEvidenceByCanonicalRef")
    ref_key = canonical(ref).decode("utf-8")
    evidence = (
        evidence_by_ref.get(ref_key, evidence_by_ref.get(ref["contentHash"]))
        if isinstance(evidence_by_ref, dict) else None
    )
    if not isinstance(evidence, dict):
        return ("indeterminate", "absence evidence cannot be dereferenced", None)
    if (
        set(evidence) != {"kind", "nativeAddress", "finalizedStateRef"}
        or evidence.get("kind") != ref["kind"]
        or not all(_nonempty_jcs_string(evidence.get(field)) for field in (
            "nativeAddress", "finalizedStateRef",
        ))
        or _canon_sha(evidence) != ref["contentHash"]
    ):
        return ("fail", "absence evidence shape or content hash is invalid", None)
    binding = authority.get("absenceBinding")
    pure_native = _pure_native_address(
        substrate,
        logical_address(job_id, role, trusted_contexts=trusted_context),
        verifier_config,
    )
    if pure_native is not None:
        if binding is not None or evidence["nativeAddress"] != pure_native:
            return ("fail", "pure-mapping absence evidence binds the wrong native address", None)
    else:
        checked = verify_binding(
            binding, current_key_authority,
            expected_jobid=job_id, expected_role=role,
            trusted_contexts=trusted_context)
        if (
            not checked["ok"]
            or binding.get("signer") != role_map[role]
            or binding.get("nativeAddress") != evidence["nativeAddress"]
        ):
            return ("fail", "absence binding does not authenticate the missing role address", None)
    return ("pass", "hash-bound role absence verified", {
        "absenceEvidenceRef": copy.deepcopy(ref),
        "absenceBinding": copy.deepcopy(binding),
    })


def _resolve_current_use_role(
    job, role, role_request, dependencies, verifier_config,
    current_key_authority, trusted_context,
):
    if not isinstance(role_request, dict):
        return {"decision": "error", "reason": "role request is not an object"}
    disposition = role_request.get("disposition")
    job_id = job["jobId"]
    substrate = job["substrate"]
    role_map, signer_map = _configured_party_maps(verifier_config, job_id)
    if role_map is None:
        return {"decision": "indeterminate", "reason": "party authority is unavailable"}
    if disposition == "indeterminate":
        if set(role_request) != {"disposition"}:
            return {"decision": "error", "reason": "indeterminate role request has unknown members"}
        return {"decision": "indeterminate", "reason": "role presence is indeterminate"}
    if disposition == "absent":
        if set(role_request) != {"disposition"}:
            return {"decision": "error", "reason": "absent role request has unknown members"}
        absence_decision, absence_reason, absence = _validate_current_use_absence(
            job_id, role, substrate, dependencies, verifier_config, role_map,
            current_key_authority, trusted_context)
        if absence_decision != "pass":
            return {"decision": absence_decision, "reason": absence_reason}
        return {
            "decision": "pass", "disposition": "absent", "reason": absence_reason,
            **absence,
        }
    if disposition != "present":
        return {"decision": "error", "reason": "role disposition is unsupported"}
    mapping_kind = role_request.get("mappingKind")
    public_keys = verifier_config.get("publicKeys")
    if mapping_kind == "pure":
        if set(role_request) - {"disposition", "mappingKind", "resolvedAddress", "anchorReceipt", "legacyEraEvidence"}:
            return {"decision": "error", "reason": "pure role request has unknown members"}
        logical = logical_address(
            job_id, role, trusted_contexts=trusted_context)
        expected_native = _pure_native_address(substrate, logical, verifier_config)
        if expected_native is None:
            return {"decision": "indeterminate", "reason": "pure-mapping verifier is unavailable"}
        if role_request.get("resolvedAddress") != expected_native:
            return {"decision": "fail", "reason": "pure role address does not match deterministic mapping"}
        bundle = _lookup_by_address(dependencies, "bundlesByNativeAddress", expected_native)
        if not isinstance(bundle, dict):
            return {"decision": "indeterminate", "reason": "pure role copy cannot be dereferenced"}
        shape_ok, _ = _bundle_shape_ok(bundle)
        if not shape_ok:
            return {"decision": "error", "reason": "pure role copy is malformed"}
        post_ok, post_reason = _post_fetch_address_valid(
            bundle, expected_native, role, bundle_hash(bundle),
            current_key_authority, expected_jobid=job_id,
            pure_mapping_resolver=lambda _job, _role: expected_native,
            trusted_contexts=trusted_context)
        if not post_ok:
            return {"decision": "fail", "reason": post_reason}
        if not _current_use_roster_matches_role_map(bundle, role_map):
            return {"decision": "fail", "reason": "bundle buyer/seller roster differs from verifier authority"}
        era = role_request.get("legacyEraEvidence")
        if (
            bundle_type(bundle) == "legacy"
            and isinstance(era, dict)
            and era.get("substrate") != substrate
        ):
            return {"decision": "fail", "reason": "legacy era substrate differs from requested substrate"}
        synthetic_binding = {
            "jobId": job_id, "role": role, "logicalAddress": logical,
            "nativeAddress": expected_native, "bundleContentHash": bundle_hash(bundle),
            "signer": role_map[role],
        }
        anchor_decision, anchor_reason = _current_anchor_join(
            role_request.get("anchorReceipt"), synthetic_binding, bundle, substrate, verifier_config)
        if anchor_decision != "pass":
            return {"decision": anchor_decision, "reason": anchor_reason}
        type_decision, type_reason, settlement = _validate_current_use_type_authority(
            bundle, dependencies, verifier_config)
        if type_decision != "pass":
            return {"decision": type_decision, "reason": type_reason}
        if bundle_type(bundle) == "legacy":
            era_decision, era_reason = validate_legacy_bundle_admission(
                bundle, era, dependencies, verifier_config)
            if era_decision != "pass":
                return {"decision": era_decision, "reason": era_reason}
        elif era is not None:
            return {"decision": "error", "reason": "legacy era evidence is attached to a non-legacy copy"}
        return {
            "decision": "pass", "reason": "pure-mapped role copy admitted", "disposition": "present",
            "bundle": bundle,
            "roleEvidence": {"kind": "address", "resolvedAddress": expected_native},
            "presence": {"bundleHash": bundle_hash(bundle), "nativeAddress": expected_native,
                         "writer": role_map[role]},
            "legacyEraEvidence": copy.deepcopy(era), "settlement": settlement,
        }
    if mapping_kind != "binding":
        return {"decision": "error", "reason": "role mapping kind is unsupported"}
    allowed = {
        "disposition", "mappingKind", "selectionContext", "anchorReceiptsByNativeAddress",
        "legacyEraEvidenceByNativeAddress",
    }
    if set(role_request) - allowed:
        return {"decision": "error", "reason": "binding role request has unknown members"}
    context = role_request.get("selectionContext")
    receipts = role_request.get("anchorReceiptsByNativeAddress")
    era_by_address = role_request.get("legacyEraEvidenceByNativeAddress", {})
    if not _selection_context_shape(context) or not isinstance(receipts, dict) or not isinstance(era_by_address, dict):
        return {"decision": "error", "reason": "binding role selection context is malformed"}
    if context["partyMap"] != signer_map:
        return {"decision": "fail", "reason": "BB-6 party map is not verifier-authenticated"}
    if context["budget"] != verifier_config.get("bb6Budget", BB6_DEFAULT_BUDGET):
        return {"decision": "fail", "reason": "BB-6 budget differs from verifier policy"}

    # Mandatory party-map prune before candidate validation or fetch.
    survivors = [candidate for candidate in context["candidateBindings"]
                 if isinstance(candidate, dict)
                 and context["partyMap"].get(candidate.get("signer")) == role]
    valid = []
    anchored = {}
    admitted_by_address = {}
    for candidate in survivors:
        checked = verify_binding(
            candidate, current_key_authority, expected_jobid=job_id,
            expected_role=role, trusted_contexts=trusted_context)
        if not checked["ok"]:
            return {"decision": "fail", "reason": "authorized BB-6 candidate does not verify: " + checked["reason"]}
        native = candidate["nativeAddress"]
        bundle = _lookup_by_address(dependencies, "bundlesByNativeAddress", native)
        if not isinstance(bundle, dict):
            return {"decision": "indeterminate", "reason": "authorized BB-6 candidate cannot be dereferenced"}
        shape_ok, _ = _bundle_shape_ok(bundle)
        if not shape_ok:
            continue
        post_ok, _ = _post_fetch_valid(bundle, candidate, public_keys)
        if not post_ok:
            continue
        if not _current_use_roster_matches_role_map(bundle, role_map):
            return {"decision": "fail", "reason": "bundle buyer/seller roster differs from verifier authority"}
        era = era_by_address.get(native)
        if (
            bundle_type(bundle) == "legacy"
            and isinstance(era, dict)
            and era.get("substrate") != substrate
        ):
            return {"decision": "fail", "reason": "legacy era substrate differs from requested substrate"}
        anchor_decision, anchor_reason = _current_anchor_join(
            receipts.get(native), candidate, bundle, substrate, verifier_config)
        if anchor_decision != "pass":
            return {"decision": anchor_decision, "reason": anchor_reason}
        type_decision, type_reason, settlement = _validate_current_use_type_authority(
            bundle, dependencies, verifier_config)
        if type_decision != "pass":
            # A required stronger proof cannot be bypassed by a weaker candidate.
            return {"decision": type_decision, "reason": type_reason}
        if bundle_type(bundle) == "legacy":
            era_decision, era_reason = validate_legacy_bundle_admission(
                bundle, era, dependencies, verifier_config)
            if era_decision != "pass":
                return {"decision": era_decision, "reason": era_reason}
        elif era is not None:
            return {"decision": "error", "reason": "legacy era evidence is attached to a non-legacy copy"}
        valid.append(candidate)
        anchored[native] = bundle
        admitted_by_address[native] = {"legacyEraEvidence": copy.deepcopy(era), "settlement": settlement}
    selection = resolve_bb6(valid, context["partyMap"], context["budget"], anchored)
    native = selection.get("resolvedNativeAddress")
    if selection.get("disposition") != "present" or native not in anchored:
        return {"decision": "indeterminate", "reason": "BB-6 did not select one authenticated role copy"}
    binding = next(candidate for candidate in valid if candidate["nativeAddress"] == native)
    bundle = anchored[native]
    admitted = admitted_by_address[native]
    return {
        "decision": "pass", "reason": "binding-backed role copy admitted", "disposition": "present",
        "bundle": bundle, "roleEvidence": {"kind": "binding", "binding": copy.deepcopy(binding)},
        "bb6Context": copy.deepcopy(context),
        "presence": {"bundleHash": bundle_hash(bundle), "nativeAddress": native,
                     "writer": binding["signer"]},
        "legacyEraEvidence": admitted["legacyEraEvidence"], "settlement": admitted["settlement"],
    }


def _current_use_execution_trace_complete(bundle, pipeline):
    """Check the signed ordinary-listing execution prefix used by current-use only."""
    summary = bundle.get("phaseSummary")
    if not isinstance(pipeline, list) or not pipeline or not isinstance(summary, list):
        return False
    if any(
        not isinstance(step, dict) or not _string_member(step.get("kind"), SUPPORTED_PHASES)
        for step in pipeline
    ):
        return False
    kinds = [step["kind"] for step in pipeline]
    for expected_index, entry in enumerate(summary):
        if (
            not isinstance(entry, dict)
            or entry.get("index") != expected_index
            or expected_index >= len(kinds)
            or entry.get("kind") != kinds[expected_index]
            or not _string_member(entry.get("outcome"), {"ok", "fail"})
        ):
            return False
    outcome = bundle.get("outcome")
    retry_indices = [index for index, entry in enumerate(summary) if "retryExhausted" in entry]
    retry_expected = (
        outcome == "failed-perm"
        and bool(summary)
        and summary[-1].get("outcome") == "fail"
        and summary[-1].get("errorClass") == "transient"
    )
    if retry_expected:
        if retry_indices != [len(summary) - 1] or summary[-1].get("retryExhausted") is not True:
            return False
    elif retry_indices:
        return False
    if outcome == "completed":
        return len(summary) == len(pipeline) and not any(
            entry.get("outcome") == "fail" and entry.get("kind") != "rate"
            for entry in summary
        )
    if outcome in {"failed-perm", "failed-counterparty"}:
        allowed_errors = {
            "failed-perm": {"permanent", "transient"},
            "failed-counterparty": {"counterparty", "settlement-atomicity"},
        }
        return bool(
            summary
            and summary[-1].get("outcome") == "fail"
            and all(entry.get("outcome") == "ok" for entry in summary[:-1])
            and _string_member(summary[-1].get("errorClass"), allowed_errors[outcome])
            and (
                summary[-1].get("errorClass") != "transient"
                or summary[-1].get("retryExhausted") is True
            )
        )
    if outcome == "failed-substrate":
        return bool(
            (
                summary
                and summary[-1].get("outcome") == "fail"
                and summary[-1].get("errorClass") == "substrate"
                and all(entry.get("outcome") == "ok" for entry in summary[:-1])
            )
            or (
                len(summary) == len(pipeline)
                and all(
                    entry.get("outcome") == "ok"
                    or (entry.get("kind") == "rate" and entry.get("outcome") == "fail")
                    for entry in summary
                )
            )
        )
    if outcome in _ABORT:
        return len(summary) < len(pipeline) and all(
            entry.get("outcome") == "ok" for entry in summary
        )
    return False


def _validate_current_use_historical_nonpayment(bundle, dependencies, verifier_config):
    """Require authenticated complete evidence before an older copy proves no payment."""
    kind = bundle_type(bundle)
    if kind == "finality-bound":
        return ("pass", "finality-bound copy uses the stronger payment path")
    authority = _authority_for_bundle(bundle, dependencies)
    if kind == "evidence-bound":
        # SEB was already executed for this exact copy by type admission.
        if _job_successful_payment_without_strong_finality(bundle, dependencies):
            return ("indeterminate", "successful historical payment lacks exact stronger finality")
        return ("pass", "authenticated EBFAB exact-set evidence establishes nonpayment")
    if kind not in {"legacy", "fault"}:
        return ("error", "unsupported historical bundle type")
    if not isinstance(authority, dict) or not isinstance(authority.get("listing"), dict):
        return ("indeterminate", "authenticated historical listing authority is unavailable")
    listing = authority["listing"]
    signature = listing.get("signature")
    role_map, _ = _configured_party_maps(verifier_config, bundle.get("jobId"))
    public_keys = verifier_config.get("publicKeys")
    signer = signature.get("signer") if isinstance(signature, dict) else None
    listing_ref = bundle.get("listingRef")
    digest = listing_hash(listing)
    if (
        role_map is None
        or not isinstance(signature, dict)
        or set(signature) != {"signer", "algorithm", "value"}
        or signer != listing.get("sellerPrimaryClaim")
        or signer != role_map["seller"]
        or signature.get("algorithm") != "ed25519"
        or not isinstance(public_keys, dict)
        or signer not in public_keys
        or not isinstance(listing_ref, dict)
        or listing_ref.get("listingId") != listing.get("listingId")
        or listing_ref.get("version") != listing.get("listingVersion")
        or listing_ref.get("contentHash") != digest
    ):
        return ("fail", "historical listing identity or signer is not verifier-authenticated")
    canonical_ok, _ = sig6_canonical(signature.get("value"))
    if not canonical_ok or not verify_sig(
        public_keys[signer], LISTING_DOMAIN, digest, signature["value"]
    ):
        return ("fail", "historical listing signature does not verify")
    pipeline = listing.get("pipeline")
    if not _current_use_execution_trace_complete(bundle, pipeline):
        return ("indeterminate", "historical execution trace is incomplete or outcome-inconsistent")
    evidence_refs = bundle.get("settlementEvidence")
    if not isinstance(evidence_refs, list):
        return ("indeterminate", "historical settlementEvidence is unavailable")
    summary = bundle["phaseSummary"]
    expected_entries = [entry for entry in summary if entry.get("kind") in EVIDENCE_PHASES]
    if not expected_entries:
        if evidence_refs:
            return ("indeterminate", "historical evidence cannot be matched to the complete execution trace")
        return ("pass", "authenticated complete historical trace establishes no payment invocation")
    if any(entry.get("kind") in PAYMENT_PHASES and entry.get("outcome") == "ok"
           for entry in expected_entries):
        return ("indeterminate", "successful historical payment lacks exact stronger finality")
    resolutions = authority.get("referenceValidationByCanonicalRef")
    execution = authority.get("sessionExecutionAuthorityByPhaseKey")
    receipts = authority.get("verifiedReceiptByCanonicalRef")
    if not all(isinstance(value, dict) for value in (resolutions, execution, receipts)):
        return ("indeterminate", "authenticated historical execution evidence is unavailable")
    raw_ids = [canonical(ref) for ref in evidence_refs if isinstance(ref, dict)]
    if len(raw_ids) != len(evidence_refs) or len(raw_ids) != len(set(raw_ids)):
        return ("fail", "historical settlementEvidence is malformed or duplicated")
    actual_keys = []
    actual_ref_by_key = {}
    for ref in evidence_refs:
        resolution = resolutions.get(canonical(ref).decode("utf-8"))
        record = resolution.get("record") if isinstance(resolution, dict) else None
        record_signature = record.get("signature") if isinstance(record, dict) else None
        if (
            not _attestation_ref_shape_valid(ref)
            or not _settlement_evidence_shape_valid(record)
            or record.get("jobId") != bundle.get("jobId")
            or ref.get("contentHash") != settlement_evidence_hash(record)
            or not isinstance(record_signature, dict)
            or record_signature.get("algorithm") != "ed25519"
            or record_signature.get("signer") not in public_keys
        ):
            return ("fail", "historical settlement evidence is not authenticated")
        canonical_ok, _ = sig6_canonical(record_signature.get("value"))
        if not canonical_ok or not verify_sig(
            public_keys[record_signature["signer"]], SETTLEMENT_EVIDENCE_DOMAIN,
            settlement_evidence_hash(record), record_signature["value"]
        ):
            return ("fail", "historical settlement evidence signature does not verify")
        binding_ok, binding_result, _ = _resolve_authenticated_evidence_binding(
            ref, record, record_signature["signer"], bundle, execution, receipts
        )
        if not binding_ok:
            return ("indeterminate", "historical settlement evidence lacks authenticated execution binding")
        phase_key, resolved = binding_result
        if (
            resolved
            or (
                record.get("phase") in PAYMENT_PHASES
                and record.get("outcome") == "success"
            )
        ):
            return ("indeterminate", "successful or superseding historical payment lacks exact stronger finality")
        if record.get("phase") in {
            "pay-cross-chain-htlc", "pay-cross-chain-liquidity-tank",
        }:
            return ("indeterminate", "historical cross-chain settlement requires stronger finality")
        summary_entry = next((
            entry for entry in expected_entries
            if phase_key == "%d:%s" % (entry["index"], entry["kind"])
        ), None)
        lifecycle = resolution.get("lifecycle")
        if (
            not isinstance(summary_entry, dict)
            or record.get("phase") != summary_entry.get("kind")
            or record.get("outcome") != ("success" if summary_entry.get("outcome") == "ok" else "failure")
            or not isinstance(lifecycle, dict)
            or not _string_member(lifecycle.get("state"), {"included", "finalized"})
        ):
            return ("fail", "historical evidence contradicts the authenticated phase result")
        actual_keys.append(phase_key)
        actual_ref_by_key[phase_key] = ref
    expected_keys = ["%d:%s" % (entry["index"], entry["kind"]) for entry in expected_entries]
    if len(actual_keys) != len(set(actual_keys)) or set(actual_keys) != set(expected_keys):
        return ("indeterminate", "historical settlementEvidence is not the complete phase-result set")
    for entry in expected_entries:
        pointer = entry.get("attestationRef")
        phase_key = "%d:%s" % (entry["index"], entry["kind"])
        if pointer is not None and canonical(pointer) != canonical(actual_ref_by_key[phase_key]):
            return ("fail", "historical phase pointer contradicts settlementEvidence")
    return ("pass", "authenticated complete historical evidence establishes nonpayment")


def _job_successful_payment_without_strong_finality(bundle, dependencies):
    authority = _authority_for_bundle(bundle, dependencies)
    if isinstance(authority, dict):
        resolutions = authority.get("referenceValidationByCanonicalRef")
        if isinstance(resolutions, dict):
            for resolution in resolutions.values():
                record = resolution.get("record") if isinstance(resolution, dict) else None
                if (
                    isinstance(record, dict)
                    and record.get("phase") in PAYMENT_PHASES
                    and record.get("outcome") == "success"
                ):
                    return True
    return any(
        isinstance(entry, dict)
        and entry.get("kind") in PAYMENT_PHASES
        and entry.get("outcome") == "ok"
        for entry in bundle.get("phaseSummary", [])
    )


def _resolve_current_use_job(
    job, dependencies, verifier_config, current_key_authority,
    trusted_context,
):
    if not isinstance(job, dict) or set(job) != {"jobId", "substrate", "roles"}:
        return {"decision": "error", "reason": "requested job has a malformed closed shape"}
    if not _nonempty_jcs_string(job.get("jobId")) or not _nonempty_jcs_string(job.get("substrate")):
        return {"decision": "error", "reason": "requested job identity or substrate is malformed"}
    roles = job.get("roles")
    if not isinstance(roles, dict) or set(roles) != {"buyer", "seller"}:
        return {"decision": "error", "reason": "both buyer and seller role requests are required"}
    resolved = {}
    for role in ("buyer", "seller"):
        result = _resolve_current_use_role(
            job, role, roles[role], dependencies, verifier_config,
            current_key_authority, trusted_context)
        if result.get("decision") != "pass":
            return result
        resolved[role] = result

    entries = []
    local_trust = copy.deepcopy(verifier_config.get("finalityTrust"))
    if not isinstance(local_trust, dict):
        return {"decision": "indeterminate", "reason": "finality trust is unavailable"}
    local_trust.setdefault("copyPresenceByJobRole", {})
    local_trust.setdefault("copyDispositionByJobRole", {})
    for role in ("buyer", "seller"):
        item = resolved[role]
        if item["disposition"] == "absent":
            local_trust["copyDispositionByJobRole"][job["jobId"] + ":" + role] = "absent"
            entries.append({"disposition": "absent", "expectedJobId": job["jobId"], "expectedRole": role})
            continue
        local_trust["copyPresenceByJobRole"][job["jobId"] + ":" + role] = copy.deepcopy(item["presence"])
        entries.append({
            "bundle": item["bundle"], "expectedJobId": job["jobId"], "expectedRole": role,
            "copyPresence": item["presence"],
            "authority": _authority_for_bundle(item["bundle"], dependencies),
        })
    reconciled = reconcile_authenticated_finality_copies(entries, verifier_config.get("publicKeys"), local_trust)
    if reconciled.get("decision") != "pass":
        return {"decision": reconciled.get("decision", "error"), "reason": reconciled.get("reason", "reconciliation failed")}
    authoritative = reconciled["bundle"]
    historical_decision, historical_reason = _validate_current_use_historical_nonpayment(
        authoritative, dependencies, verifier_config)
    if historical_decision != "pass":
        return {"decision": historical_decision, "reason": historical_reason}
    role_of_party = _role_of_party(authoritative, verifier_config.get("scoredParty"))
    present_results = [resolved[role] for role in ("buyer", "seller") if resolved[role]["disposition"] == "present"]
    selected = next((item for item in present_results
                     if item["bundle"].get("anchoredByRole") == authoritative.get("anchoredByRole")
                     and bundle_hash(item["bundle"]) == bundle_hash(authoritative)), present_results[0])
    pair_faults = set()
    if len(present_results) == 2:
        pair_faults = common_fault_set(present_results[0]["bundle"], present_results[1]["bundle"])
    return {
        "decision": "pass", "reason": "requested job fully admitted", "bundle": authoritative,
        "roleOfParty": role_of_party, "selected": selected, "roles": resolved,
        "pairFaults": pair_faults,
    }


def _artifact_from_ref(dependencies, collection, ref):
    values = dependencies.get(collection) if isinstance(dependencies, dict) else None
    if not isinstance(values, dict) or not isinstance(ref, dict):
        return None
    key = canonical(ref).decode("utf-8")
    return values.get(key, values.get(ref.get("contentHash")))


def _rating_record(bundle, ref, dependencies, verifier_config):
    record = _artifact_from_ref(dependencies, "ratingsByCanonicalRef", ref)
    required = {"ratingVersion", "jobId", "rater", "target", "targetRole", "value", "ratedAt", "signature"}
    optional = {"freeText", "dimensions"}
    if not isinstance(record, dict) or not required <= set(record) <= required | optional:
        return None
    if (
        record.get("ratingVersion") != "1"
        or record.get("jobId") != bundle.get("jobId")
        or not all(_nonempty_jcs_string(record.get(field)) for field in ("rater", "target"))
        or not _string_member(record.get("targetRole"), {"buyer", "seller"})
        or not isinstance(record.get("value"), int)
        or isinstance(record.get("value"), bool)
        or not 1 <= record["value"] <= 5
        or not _non_boolean_number(record.get("ratedAt"))
        or ("freeText" in record and (not isinstance(record["freeText"], str) or len(record["freeText"]) > 1000))
        or not _attestation_ref_shape_valid(ref)
        or ref.get("contentHash") != _jcs_hash(record, "signature")
    ):
        return None
    signature = record.get("signature")
    public_keys = verifier_config.get("publicKeys")
    if (
        not isinstance(signature, dict)
        or set(signature) != {"signer", "algorithm", "value"}
        or signature.get("signer") != record.get("rater")
        or signature.get("algorithm") != "ed25519"
        or record.get("rater") not in public_keys
    ):
        return None
    canonical_ok, _ = sig6_canonical(signature.get("value"))
    if not canonical_ok or not verify_sig(
        public_keys[record["rater"]], RATING_DOMAIN,
        _jcs_hash(record, "signature"), signature["value"]):
        return None
    return record


def _decimal_text(value):
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _group_prices(terms):
    sums = {}
    counts = {}
    for term in terms:
        currency = term["currency"]
        sums[currency] = sums.get(currency, Decimal(0)) + Decimal(term["amount"])
        counts[currency] = counts.get(currency, 0) + 1
    volume = [{"amount": _decimal_text(sums[currency]), "currency": currency}
              for currency in sorted(sums)]
    count_rows = [{"currency": currency, "count": counts[currency]} for currency in sorted(counts)]
    return volume, count_rows


def _current_use_settlement_tx_ids(record):
    """Project the SB-1 settlement identities defined by DACS-4 §9.5.8.

    Finality/RSV has already authenticated these signed references.  HTLC,
    liquidity-tank, and AP2 use their separately defined session/replay bindings;
    §9.5.8 does not define an additional string projection for those arms.
    """
    refs = record.get("paymentTxRefs") if isinstance(record, dict) else None
    if not isinstance(refs, list):
        return None
    projected = []
    for ref in refs:
        if not isinstance(ref, dict):
            return None
        kind = ref.get("kind")
        if kind in {"evm-event", "x402-event"}:
            chain_id = ref.get("chainId")
            index = ref.get("logIndex")
            tx_hash = ref.get("txHash") if kind == "evm-event" else ref.get("settlementTxHash")
            if (
                not _safe_nonnegative_integer(chain_id) or chain_id == 0
                or not _safe_nonnegative_integer(index)
                or not _sha256_hex(tx_hash)
            ):
                return None
            projected.append("evm:%d:%s:%d" % (chain_id, tx_hash, index))
        elif kind == "solana-instruction":
            cluster = ref.get("cluster")
            signature = ref.get("signature")
            index = ref.get("instructionIndex")
            if (
                not _nonempty_jcs_string(cluster)
                or not _nonempty_jcs_string(signature)
                or not _safe_nonnegative_integer(index)
            ):
                return None
            projected.append("solana:%s:%s:%d" % (cluster, signature, index))
        elif kind == "demos":
            tx_hash = ref.get("txHash")
            if not _sha256_hex(tx_hash):
                return None
            projected.append("demos:" + tx_hash)
    return projected


def _current_use_sb2_conflict(reconciled):
    claims = {}
    for result in reconciled:
        settlement = result["selected"]["settlement"]
        for payment in settlement.get("successfulPayments", []):
            record = payment.get("record") if isinstance(payment, dict) else None
            phase_index = payment.get("phaseIndex") if isinstance(payment, dict) else None
            if not isinstance(record, dict) or not _safe_nonnegative_integer(phase_index):
                return "authenticated settlement identity context is malformed"
            keys = _current_use_settlement_tx_ids(record)
            if keys is None:
                return "authenticated settlement identity cannot be projected"
            binding = (record.get("jobId"), phase_index)
            for key in keys:
                prior = claims.get(key)
                if prior is not None and prior != binding:
                    # DACS-4 rejects the later record.  CUR-2 is all-or-nothing, so
                    # this stronger request emits no partial result from the winner.
                    return "settlement-tx-id is rebound across requested jobs"
                claims[key] = binding
    return None


def _agreement_price(bundle, selected, dependencies):
    agreement_ref = bundle.get("agreementRef")
    if not isinstance(agreement_ref, dict):
        return None
    agreement = _artifact_from_ref(dependencies, "agreementsByCanonicalRef", agreement_ref)
    if not isinstance(agreement, dict) or agreement_ref.get("contentHash") != _jcs_hash(agreement, "signatures"):
        return None
    # For a finality-bound payment, verify_finality already authenticated this exact
    # agreement against the committed session.  Require object equality here so the
    # volume resolver cannot swap a merely hash-shaped price source.
    authority = _authority_for_bundle(bundle, dependencies)
    candidates = authority.get("finalityVerificationByCanonicalRef") if isinstance(authority, dict) else None
    exact = [candidate.get("agreement") for candidate in candidates.values()
             if isinstance(candidate, dict)] if isinstance(candidates, dict) else []
    if not exact or any(candidate != agreement for candidate in exact):
        return None
    terms = agreement.get("terms")
    price = terms.get("price") if isinstance(terms, dict) else None
    if not _price_term_shape_valid(price):
        return None
    return {"amount": price["amount"], "currency": price["currency"]}


def _resolution_context_entry(job_result):
    bundle = job_result["bundle"]
    selected = job_result["selected"]
    entry = {
        "resolvedJobId": bundle["jobId"],
        "contentHash": bundle_hash(bundle),
        "resolvedRole": bundle["anchoredByRole"],
        "bundleType": bundle_type(bundle),
        "roleEvidence": copy.deepcopy(selected["roleEvidence"]),
        "counterpartyDisposition": "present" if all(
            job_result["roles"][role]["disposition"] == "present" for role in ("buyer", "seller")
        ) else "absent",
        "finalityClasses": sorted(selected["settlement"]["finalityClasses"]),
    }
    if selected.get("bb6Context") is not None:
        entry["bb6Context"] = copy.deepcopy(selected["bb6Context"])
    if selected.get("legacyEraEvidence") is not None:
        entry["legacyEraEvidence"] = copy.deepcopy(selected["legacyEraEvidence"])
    other_role = _other(entry["resolvedRole"])
    other = job_result["roles"].get(other_role)
    if isinstance(other, dict) and other.get("disposition") == "present":
        entry["counterpartyRef"] = {
            "anchor": {
                "kind": "storage-program",
                "locator": _role_evidence_locator(other["roleEvidence"]),
            },
            "contentHash": bundle_hash(other["bundle"]),
        }
        entry["counterpartyRoleEvidence"] = copy.deepcopy(other["roleEvidence"])
        if other.get("legacyEraEvidence") is not None:
            entry["counterpartyLegacyEraEvidence"] = copy.deepcopy(other["legacyEraEvidence"])
    elif isinstance(other, dict) and other.get("disposition") == "absent":
        entry["absenceEvidenceRef"] = copy.deepcopy(other["absenceEvidenceRef"])
        if other.get("absenceBinding") is not None:
            entry["absenceBinding"] = copy.deepcopy(other["absenceBinding"])
    return entry


def _build_current_use_derivation(
    party, requests, admitted, window_start, window_end, basis, computed_at,
    dependencies, verifier_config,
):
    reconciled = []
    for result in admitted:
        bundle = result["bundle"]
        timestamp = bundle.get(basis)
        if not _non_boolean_number(timestamp):
            return _current_use_result("error", "admitted bundle window clock is malformed")
        if party not in _primary_claims(bundle) or result.get("roleOfParty") not in {"buyer", "seller"}:
            return _current_use_result("fail", "requested party is not an authenticated buyer or seller")
        if window_start <= timestamp <= window_end:
            reconciled.append(result)

    sb2_conflict = _current_use_sb2_conflict(reconciled)
    if sb2_conflict is not None:
        return _current_use_result("fail", sb2_conflict)

    outcomes = [scored_outcome(result["bundle"], result["roleOfParty"]) for result in reconciled]
    orchestrator_fault = {
        result["bundle"]["jobId"] for result in reconciled
        if ((is_fab(result["bundle"]) and result["bundle"].get("faultedParty") == "orchestrator")
            or result["pairFaults"] == {"orchestrator"})
    }
    cancelled = set()
    cancellation_authority = verifier_config.get("cancellationDecisionByJob")
    for result in reconciled:
        bundle = result["bundle"]
        markers = [item["bundle"].get("cancellation") for item in result["roles"].values()
                   if item.get("disposition") == "present" and item["bundle"].get("cancellation") is not None]
        if not markers:
            continue
        decision = cancellation_authority.get(bundle["jobId"]) if isinstance(cancellation_authority, dict) else None
        if decision is None:
            return _current_use_result("indeterminate", "cancellation authority is unavailable")
        if decision not in {"permitted", "forbidden"}:
            return _current_use_result("error", "cancellation authority decision is malformed")
        if decision == "permitted":
            cancelled.add(bundle["jobId"])

    n = len(reconciled)
    completed_count = sum(outcome == "completed" for outcome in outcomes)
    failed_substrate = {result["bundle"]["jobId"] for result, outcome in zip(reconciled, outcomes)
                        if outcome == "failed-substrate"}
    counterparty_fault = sum(
        outcome in {"failed-counterparty", "aborted-by-other"}
        and result["bundle"]["jobId"] not in cancelled
        and result["bundle"]["jobId"] not in orchestrator_fault
        for result, outcome in zip(reconciled, outcomes)
    )
    party_fault_denom = n - len(failed_substrate | cancelled | orchestrator_fault)
    blame_denom = party_fault_denom - counterparty_fault

    rating_winners = {}
    for result in reconciled:
        bundle = result["bundle"]
        party_claims = _primary_claims(bundle)
        for ref in bundle.get("ratingRefs", []) or []:
            record = _rating_record(bundle, ref, dependencies, verifier_config)
            if (
                record is None or record["rater"] not in party_claims
                or record["rater"] == party or record["target"] != party
            ):
                continue
            key = (record["rater"], record["jobId"], record["targetRole"])
            identity = (_non_boolean_number(record["ratedAt"]) and record["ratedAt"], _jcs_hash(record, "signature"))
            previous = rating_winners.get(key)
            if previous is None or identity > previous[0]:
                rating_winners[key] = (identity, record)
    buyer_ratings = [item[1]["value"] for item in rating_winners.values()
                     if item[1]["targetRole"] == "buyer"]
    seller_ratings = [item[1]["value"] for item in rating_winners.values()
                      if item[1]["targetRole"] == "seller"]

    all_terms = []
    profile_final_terms = []
    provider_terms = []
    for result, outcome in zip(reconciled, outcomes):
        if outcome != "completed" or bundle_type(result["bundle"]) != "finality-bound":
            continue
        classes = result["selected"]["settlement"]["finalityClasses"]
        records = result["selected"]["settlement"]["records"]
        has_success = any(record.get("phase") in PAYMENT_PHASES and record.get("outcome") == "success"
                          for record in records)
        if not has_success:
            continue
        price = _agreement_price(result["bundle"], result["selected"], dependencies)
        if price is None:
            # An agreementRef that cannot be authenticated makes the requested
            # stronger metrics unverifiable; no fabricated zero/partial output.
            if "agreementRef" in result["bundle"]:
                return _current_use_result("indeterminate", "volume agreement cannot be authenticated")
            continue
        all_terms.append(price)
        if "provisional-provider-capture" in classes:
            provider_terms.append(price)
        else:
            profile_final_terms.append(price)
    observed_volume, observed_counts = _group_prices(all_terms)
    profile_volume, profile_counts = _group_prices(profile_final_terms)
    provider_volume, provider_counts = _group_prices(provider_terms)

    ordered = sorted(reconciled, key=lambda result: (bundle_hash(result["bundle"]), result["bundle"]["jobId"]))
    resolution_context = [_resolution_context_entry(result) for result in ordered]
    metrics = {
        "completionRate": completed_count / party_fault_denom if party_fault_denom > 0 else None,
        "counterpartyAdjustedCompletionRate": completed_count / blame_denom if blame_denom > 0 else None,
        "counterpartyFaultRate": counterparty_fault / party_fault_denom if party_fault_denom > 0 else None,
        "averageBuyerRating": (sum(buyer_ratings) / len(buyer_ratings)) if buyer_ratings else None,
        "averageSellerRating": (sum(seller_ratings) / len(seller_ratings)) if seller_ratings else None,
        "observedTransactionalVolume": observed_volume,
        "transactionCountByCurrency": observed_counts,
        "finalityClassifiedVolume": {
            "profileFinal": {
                "observedTransactionalVolume": profile_volume,
                "transactionCountByCurrency": profile_counts,
            },
            "provisionalProviderCapture": {
                "observedTransactionalVolume": provider_volume,
                "transactionCountByCurrency": provider_counts,
            },
        },
    }
    derivation = {
        "currentUseReplayableDerivationVersion": "1",
        "partyPrimaryClaim": party,
        "windowStart": window_start,
        "windowEnd": window_end,
        "bundleCount": len(ordered),
        "metrics": metrics,
        "computedAt": computed_at,
        "windowingBasis": basis,
        "bundleRefs": [
            {
                "anchor": {
                    "kind": "storage-program",
                    "locator": _role_evidence_locator(result["selected"]["roleEvidence"]),
                },
                "contentHash": bundle_hash(result["bundle"]),
            }
            for result in ordered
        ],
        "resolutionContext": resolution_context,
        "requestContext": copy.deepcopy(requests),
    }
    return _current_use_result("pass", "all requested jobs admitted and current-use metrics computed", derivation)


def _current_use_request_admission(
    party, requests, window_start, window_end, basis, verifier_config,
    current_key_authority, trusted_context,
):
    """Authenticate current query, exact-profile roles, JIDs, and key capability.

    This runs before any dependency resolution. ``partyRolesByJob`` is only a
    verifier-configured consistency input: it cannot create role/profile or key
    authority, which must arrive independently through ``trusted_context`` and
    ``current_key_authority``.
    """
    if not _current_context_shape_valid(trusted_context):
        return ("indeterminate", "current-profile-admission", None)
    query = trusted_context.get("query")
    if (
        not isinstance(query, dict)
        or query.get("authenticated") is not True
        or query.get("party") != party
        or type(query.get("windowStart")) is not type(window_start)
        or query.get("windowStart") != window_start
        or type(query.get("windowEnd")) is not type(window_end)
        or query.get("windowEnd") != window_end
        or query.get("windowingBasis") != basis
        or not is_exact_corrective_profile(query.get("profile"))
    ):
        return ("fail", "current-query-admission", None)
    keys = _authenticated_current_key_map(current_key_authority)
    if keys is None:
        return ("indeterminate", "current-crypto-admission", None)

    job_ids = []
    for index, job in enumerate(requests):
        if not isinstance(job, dict):
            return ("error", "requested job[%d] is not an object" % index, None)
        job_id = job.get("jobId")
        try:
            validate_current_job_id(job_id)
        except ValueError:
            return ("error", "requested job[%d]: job-id-validation" % index, None)
        job_ids.append(job_id)
    if len(job_ids) != len(set(job_ids)):
        return ("error", "requested jobIds must be unique", None)

    configured_by_job = verifier_config.get("partyRolesByJob")
    if not isinstance(configured_by_job, dict):
        return ("indeterminate", "party authority is unavailable", None)
    for job_id in job_ids:
        authenticated_roles = {
            role: resolve_current_profile(job_id, role, trusted_context)
            for role in ("buyer", "seller")
        }
        if any(identity is None for identity in authenticated_roles.values()):
            return (
                "indeterminate",
                "%s: exact-profile buyer/seller authority is unavailable" % job_id,
                None,
            )
        configured_roles = configured_by_job.get(job_id)
        if (
            not isinstance(configured_roles, dict)
            or set(configured_roles) != {"buyer", "seller"}
        ):
            return ("indeterminate", "%s: party authority is unavailable" % job_id, None)
        if configured_roles != authenticated_roles:
            return (
                "fail",
                "%s: verifier partyRolesByJob differs from authenticated role authority" % job_id,
                None,
            )
        if any(identity not in keys for identity in authenticated_roles.values()):
            return (
                "indeterminate",
                "%s: authenticated buyer/seller key capability is unavailable" % job_id,
                None,
            )
        if party not in authenticated_roles.values():
            return (
                "fail",
                "%s: query party is not an authenticated buyer or seller" % job_id,
                None,
            )
    return ("pass", "current request authority admitted", keys)


def derive_current_use_replayable(
    party, requests, window_start, window_end, dependencies, verifier_config,
    basis="finalisedAt", computed_at=None, *, pubkeys=None,
    trusted_contexts=None,
):
    """Execute the complete current-use contract or return no derivation.

    ``requests`` is the caller's explicit stronger request.  Every requested job
    must pass the full dependency chain before any metric is emitted.  The output
    is unsigned derivation data; all authority remains in ``verifier_config`` and
    authenticated dependency artifacts.
    """
    try:
        if not _nonempty_jcs_string(party):
            return _current_use_result("error", "partyPrimaryClaim is malformed")
        if not isinstance(requests, list):
            return _current_use_result("error", "requestContext must be an array")
        if not isinstance(dependencies, dict) or not isinstance(verifier_config, dict):
            return _current_use_result("indeterminate", "dependency or verifier configuration is unavailable")
        if basis not in IMPLEMENTED_WINDOWING_BASES:
            decision = "indeterminate" if basis in SUPPORTED_WINDOWING_BASES else "error"
            return _current_use_result(decision, "requested windowing basis is unsupported")
        if not _non_boolean_number(window_start) or not _non_boolean_number(window_end) or window_start > window_end:
            return _current_use_result("error", "window bounds are malformed")
        admission, admission_reason, keys = _current_use_request_admission(
            party, requests, window_start, window_end, basis, verifier_config,
            pubkeys, trusted_contexts)
        if admission != "pass":
            return _current_use_result(admission, admission_reason)
        if computed_at is None:
            computed_at = verifier_config.get("verificationTimeMs")
        if not _non_boolean_number(computed_at):
            return _current_use_result("indeterminate", "verifier-local computation time is unavailable")
        config = dict(verifier_config)
        config["publicKeys"] = keys
        config["scoredParty"] = party
        admitted = []
        for job in requests:
            result = _resolve_current_use_job(
                job, dependencies, config, pubkeys, trusted_contexts)
            if result.get("decision") != "pass":
                return _current_use_result(
                    result.get("decision", "error"),
                    "%s: %s" % (job.get("jobId", "<malformed>") if isinstance(job, dict) else "<malformed>",
                                  result.get("reason", "admission failed")))
            admitted.append(result)
        return _build_current_use_derivation(
            party, requests, admitted, window_start, window_end, basis, computed_at,
            dependencies, config)
    except (KeyError, TypeError, ValueError, UnicodeError, OverflowError,
            InvalidOperation, RecursionError):
        return _current_use_result("error", "current-use request contains malformed nested data")


def replay_current_use_derivation(
    derivation, dependencies, verifier_config, *, pubkeys=None,
    trusted_contexts=None,
):
    """Re-run every dependency and compare the complete current-use result."""
    gate = require_current_use_replayable_derivation(derivation)
    if not gate["ok"]:
        return {"ok": False, "reason": "discriminator refusal: " + gate["reason"], "replayed": None}
    required = {
        "currentUseReplayableDerivationVersion", "partyPrimaryClaim", "windowStart", "windowEnd",
        "bundleCount", "metrics", "computedAt", "windowingBasis", "bundleRefs",
        "resolutionContext", "requestContext",
    }
    if set(derivation) != required:
        return {"ok": False, "reason": "current-use derivation has a malformed closed shape", "replayed": None}
    if (
        not isinstance(derivation.get("metrics"), dict)
        or not isinstance(derivation.get("bundleRefs"), list)
        or not isinstance(derivation.get("resolutionContext"), list)
        or not isinstance(derivation.get("requestContext"), list)
        or not isinstance(derivation.get("bundleCount"), int)
        or isinstance(derivation.get("bundleCount"), bool)
    ):
        return {"ok": False, "reason": "current-use derivation containers are malformed", "replayed": None}
    result = derive_current_use_replayable(
        derivation["partyPrimaryClaim"], derivation["requestContext"],
        derivation["windowStart"], derivation["windowEnd"], dependencies,
        verifier_config, basis=derivation["windowingBasis"],
        computed_at=derivation["computedAt"], pubkeys=pubkeys,
        trusted_contexts=trusted_contexts)
    if result["decision"] != "pass":
        return {"ok": False, "reason": "full dependency replay did not pass: " + result["reason"], "replayed": None}
    replayed = result["derivation"]
    try:
        same = _new_type_canonical(replayed) == _new_type_canonical(derivation)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return {"ok": False, "reason": "current-use derivation is not canonicalizable", "replayed": None}
    return {
        "ok": same,
        "reason": "complete current-use derivation reproduced" if same else "complete current-use derivation differs",
        "replayed": replayed,
    }


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
    )
