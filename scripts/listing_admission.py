"""Exact Listing admission bridge for the current corrective-profile consumers.

This is a compatibility bridge, not a re-introduction of the removed consumer
dispatch. It consumes the portable ``rsc-current-admission-v2`` result
(``joined_current_state`` plus ``validate_listing_capacity``) and issues a
verifier-owned :class:`AdmittedListing`. No admission authority is ever decoded
from artifact data or caller fields: the retained capability revalidates exact
bytes on every use and fails closed on any substitution, key mismatch, stale
evidence, or capacity failure.

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

try:
    from jcs import canonicalize as jcs_canonicalize
except ImportError:  # imported as scripts.listing_admission by tests
    from scripts.jcs import canonicalize as jcs_canonicalize

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import listing_artifact
from rsc_current_admission import (
    CONFORMANCE_SUBSTRATE,
    CONFORMANCE_FINALITY,
    joined_current_state,
    validate_listing_capacity,
)

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
    """Minimal adapter: consume the v2 join/capacity result and issue exact admission.

    Returns ``(verdict, reason, AdmittedListing | None)``. A
    ``RevocationBoundListing`` additionally requires the v2 common-state join and
    its exact content binding.
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
    publisher = listing.get("seller", {}).get("identity", {}).get("presentedBy")
    if not isinstance(signature, dict) or not isinstance(publisher, str):
        return "indeterminate", "listing signature or publisher is unavailable", None
    if signature.get("signer") != publisher or publisher != f"key:{inclusion_key}":
        return "rejected", "listing signer or publisher key is not exact", None
    if not _verify_listing_signature(listing, domain, inclusion_key):
        return "rejected", "listing signature does not verify under the inclusion key", None

    if listing_type == listing_artifact.REVOCATION_BOUND_LISTING:
        if not joined_current_state(
            current_listing_evidence, current_state_evidence, trusted_state or {}
        ):
            return "indeterminate", "current-state evidence is unavailable or mismatched", None

    if native_binding is not None:
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

    ref = exact_listing_ref(listing)
    return "verified", "verified", AdmittedListing(
        "verified",
        listing_type,
        (ref["listingId"], ref["version"], ref["contentHash"]),
        publisher,
        inclusion_key,
        session_boundary,
    )


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
    """Build a verifier-owned capability that replays the v2 gate on every use.

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
