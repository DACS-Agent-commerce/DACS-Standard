"""Exact Listing admission bridge for the current corrective-profile consumers.

This is a partial compatibility bridge, not a complete DACS-1 evaluator. It
never promotes caller-supplied lifecycle labels, current-state labels, or
partial local checks into admission authority. A new-session capability
requires an authoritative ordered DACS-1 evaluator; an already-committed
exception requires authenticated prior commitment bound to the exact Listing.
This module has neither verifier and therefore returns indeterminate without
issuing an :class:`AdmittedListing` for either direct call.

Every admission entry point returns a three-value ``(verdict, reason, record)``
tuple where ``verdict`` is ``"verified"``, ``"rejected"``, or ``"indeterminate"``
and ``record`` is an :class:`AdmittedListing` only when the verdict is
``"verified"``. This preserves the consumer-facing ternary disposition the
corrective-profile consumers already use.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import re
from dataclasses import dataclass

if __package__:
    from .jcs import canonicalize as jcs_canonicalize
    from . import listing_artifact
    from .rsc_current_admission import (
        CONFORMANCE_SUBSTRATE,
        CONFORMANCE_FINALITY,
        validate_listing_capacity,
    )
else:  # direct-script and scripts-on-path consumers
    from jcs import canonicalize as jcs_canonicalize
    import listing_artifact
    from rsc_current_admission import (
        CONFORMANCE_SUBSTRATE,
        CONFORMANCE_FINALITY,
        validate_listing_capacity,
    )

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_HEX = re.compile(r"[0-9a-f]{64}\Z")
SESSION_BOUNDARIES = frozenset({
    "new-session",
    "past-authenticated-agreement-commitment",
})


def canonical_bytes(value) -> bytes:
    return jcs_canonicalize(value).encode("utf-8")


def listing_content_hash(listing) -> str:
    """Canonical signature-omitted Listing content hash (JCS §B.2 scope)."""
    unsigned = {
        key: value for key, value in listing.items() if key != "signature"
    }
    return hashlib.sha256(canonical_bytes(unsigned)).hexdigest()


def exact_listing_ref(listing) -> dict:
    """The exact Listing identity reference bound by the admission."""
    return {
        "listingId": listing.get("listingId"),
        "version": listing.get("listingVersion"),
        "contentHash": listing_content_hash(listing),
    }


def _b64url_decode(value) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("non-canonical Base64URL")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise ValueError("non-canonical Base64URL")
    return decoded


def _verify_listing_signature(listing, domain, key_hex) -> bool:
    signature = listing.get("signature")
    if (
        not isinstance(signature, dict)
        or signature.get("algorithm") != "ed25519"
        or not isinstance(signature.get("value"), str)
    ):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(
            _b64url_decode(signature["value"]),
            (domain + listing_content_hash(listing)).encode("ascii"),
        )
    except (TypeError, ValueError, InvalidSignature):
        return False
    return True


@dataclass(frozen=True)
class AdmittedListing:
    """Verifier-issued exact Listing admission; never a serializable artifact."""

    disposition: str
    listing_type: str
    listing_ref: tuple  # (listingId, version, contentHash)
    publisher: str
    inclusion_key: str  # 64-hex publisher key, distinct from every other key role
    session_boundary: str


class ListingAdmissionCapability:
    """Explicit local capability for revalidating one exact DACS-1 admission.

    Callers select this object rather than wiring admission data. The callback
    returns ``(verdict, reason, AdmittedListing | None)``; bools, dictionaries,
    and other caller-minted values carry no authority at this boundary.
    """

    __slots__ = ("_callback",)

    def __init__(self, callback):
        if not callable(callback):
            raise TypeError("listing admission callback must be callable")
        self._callback = callback

    def verify(self, listing, listing_ref, session_boundary):
        try:
            return self._callback(listing, listing_ref, session_boundary)
        except (AttributeError, KeyError, OverflowError, TypeError, ValueError):
            return "indeterminate", "listing admission verifier failed", None


def admit_listing(
    listing,
    *,
    inclusion_key,
    session_boundary,
    native_binding=None,
    current_listing_evidence=None,
    current_state_evidence=None,
    trusted_state=None,
):
    """Run partial checks, but never issue an unauthenticated admission.

    Returns ``(verdict, reason, AdmittedListing | None)``. A local signature,
    shape, current-state label join, or capacity check is not the normative
    ordered DACS-1 admission (profile, time, RSC, identity, phase, rail, and
    finalized anchor). Nor does a caller's committed-session string prove an
    authenticated prior agreement commitment. Current-evidence arguments
    remain for API compatibility but cannot authorize either boundary.
    """
    if not isinstance(listing, dict):
        return "rejected", "listing is not an object", None
    if session_boundary not in SESSION_BOUNDARIES:
        return "indeterminate", "listing admission session boundary is unsupported", None
    try:
        listing_type, domain = listing_artifact.classify_listing_artifact(listing)
    except ValueError:
        return "rejected", "listing discriminator is invalid", None
    shape_ok, _, _, _ = listing_artifact.validate_listing_shape(listing)
    if not shape_ok:
        return "rejected", "listing shape is invalid", None
    if not isinstance(inclusion_key, str) or _HEX.fullmatch(inclusion_key) is None:
        return "indeterminate", "listing inclusion key is unavailable", None
    signature = listing.get("signature")
    identity = listing.get("seller", {}).get("identity", {})
    claims = identity.get("claims") if isinstance(identity, dict) else None
    signer = signature.get("signer") if isinstance(signature, dict) else None
    if not isinstance(signer, str) or not isinstance(claims, list):
        return "indeterminate", "listing signature or seller claims are unavailable", None
    if not any(isinstance(claim, dict) and claim.get("ref") == signer for claim in claims):
        return "rejected", "listing signer is absent from seller claims", None
    if signer != f"key:{inclusion_key}":
        if signer.startswith("key:"):
            return "rejected", "listing signer key does not match the inclusion key", None
        return "indeterminate", "listing signer key resolution is unavailable", None
    if not _verify_listing_signature(listing, domain, inclusion_key):
        return "rejected", "listing signature does not verify under the inclusion key", None

    if session_boundary == "new-session" or native_binding is not None:
        capacity = validate_listing_capacity(
            listing,
            native_binding,
            substrate=CONFORMANCE_SUBSTRATE,
            finality_profile=CONFORMANCE_FINALITY,
        )
        if capacity == "fail":
            return "rejected", "listing exceeds the native-capacity limit", None
        if capacity != "pass":
            return "indeterminate", "native-capacity evidence is unavailable", None

    if session_boundary == "new-session":
        if not isinstance(listing.get("revocationState"), dict):
            return "indeterminate", "current revocation-state reference is unavailable", None
        # The portable v2 join compares already-authenticated child results;
        # these public dict parameters are not those results. More importantly,
        # no full ordered DACS-1 evaluator is installed here. Do not issue a
        # capability from signature, shape, capacity, or caller labels alone.
        return "indeterminate", "full DACS-1 new-session admission is unavailable", None

    # RSC-8 preserves already-committed sessions, but the caller's boundary
    # string does not authenticate that state or bind its agreement/listingRef.
    # A separate verifier-owned prior admission is needed for retained use.
    return "indeterminate", "authenticated committed-session admission is unavailable", None

def retained_listing_admission(
    listing,
    listing_ref,
    *,
    inclusion_key,
    session_boundary,
    native_binding=None,
    current_listing_evidence=None,
    current_state_evidence=None,
    trusted_state=None,
):
    """Retain exact inputs for rechecking; this partial bridge cannot mint authority.

    All inputs are deep-copied so a later caller mutation cannot mint authority.
    A caller-substituted listing or reference never re-enters the retained gate.
    """
    retained_listing = copy.deepcopy(listing)
    retained_ref = copy.deepcopy(listing_ref)
    retained_binding = copy.deepcopy(native_binding)
    retained_listing_evidence = copy.deepcopy(current_listing_evidence)
    retained_state_evidence = copy.deepcopy(current_state_evidence)
    retained_trusted = copy.deepcopy(trusted_state)

    def revalidate(candidate, candidate_ref, boundary):
        if (
            not isinstance(candidate, dict)
            or not isinstance(candidate_ref, dict)
            or boundary != session_boundary
            or canonical_bytes(candidate) != canonical_bytes(retained_listing)
            or canonical_bytes(candidate_ref) != canonical_bytes(retained_ref)
        ):
            return "rejected", "substituted or stale listing", None
        return admit_listing(
            retained_listing,
            inclusion_key=inclusion_key,
            session_boundary=session_boundary,
            native_binding=retained_binding,
            current_listing_evidence=retained_listing_evidence,
            current_state_evidence=retained_state_evidence,
            trusted_state=retained_trusted,
        )

    return ListingAdmissionCapability(revalidate)
