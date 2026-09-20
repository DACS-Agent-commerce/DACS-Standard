"""Pinned, test-only prior Listing admission for pristine IBH terminal scenarios.

This fixture models a verifier-owned retained DACS-1 Listing admission, not a
production discovery, inclusion-key, or storage-provider adapter. Authority is
established before scenario materialization and is never inferred from a
modified Listing, an expected vector verdict, or an outer signature.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import jcs  # noqa: E402
import listing_admission  # noqa: E402
from rsc_current_admission import (  # noqa: E402
    CONFORMANCE_SUBSTRATE,
    CONFORMANCE_FINALITY,
    TrustedNativeRecordBinding,
)

CORPUS = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "identity-bundle-hash-binding-v0.1.json"
)
CORPUS_SHA256 = "7e219a773310d1cbfeecadd5fb7d5d54a5e15e0e962a50492e92c7fcd3b0dbf6"
COMMITTED_BOUNDARY = "past-authenticated-agreement-commitment"


def _native_encode(listing):
    return jcs.canonicalize({
        "fixtureRecord": listing,
        "encoding": "ibh-positive-fixture-canonical-native-envelope-v1",
    }).encode("utf-8")


def native_binding(record_limit: int = 65536) -> TrustedNativeRecordBinding:
    return TrustedNativeRecordBinding(
        CONFORMANCE_SUBSTRATE,
        CONFORMANCE_FINALITY,
        "ibh-positive-fixture-canonical-native-envelope-v1",
        record_limit,
        _native_encode,
    )


def _scenario_baseline(scenario: str) -> dict:
    raw = CORPUS.read_bytes()
    if hashlib.sha256(raw).hexdigest() != CORPUS_SHA256:
        raise ValueError("pristine IBH fixture source pin changed")
    scenarios = json.loads(raw)["scenarios"]
    if scenario not in scenarios:
        raise ValueError("scenario has no retained positive Listing admission")
    return copy.deepcopy(scenarios[scenario])


def retained_positive_admission(scenario: str) -> listing_admission.ListingAdmissionCapability:
    """Return a capability from pinned pristine source, before materialization."""
    baseline = _scenario_baseline(scenario)
    listing = baseline.get("listing")
    agreement = baseline.get("agreement")
    if not isinstance(listing, dict) or not isinstance(agreement, dict):
        raise ValueError("pristine IBH fixture baseline is invalid")
    listing_ref = agreement.get("listingRef")
    publisher = listing.get("seller", {}).get("identity", {}).get("presentedBy")
    if (
        not isinstance(listing_ref, dict)
        or not isinstance(publisher, str)
        or not publisher.startswith("key:")
    ):
        raise ValueError("pristine IBH fixture baseline is invalid")
    inclusion_key = publisher.removeprefix("key:")
    # Confirm the retained admission actually verifies against the pristine bytes
    # before exposing it to any consumer, so no broken fixture can mint authority.
    disposition, reason, _ = listing_admission.admit_listing(
        listing,
        inclusion_key=inclusion_key,
        session_boundary=COMMITTED_BOUNDARY,
        native_binding=native_binding(),
    )
    if disposition != "verified":
        raise ValueError("pristine Listing admission did not verify: %r" % ((disposition, reason),))
    return listing_admission.retained_listing_admission(
        listing,
        listing_ref,
        inclusion_key=inclusion_key,
        session_boundary=COMMITTED_BOUNDARY,
        native_binding=native_binding(),
    )


def retained_admission_for_context(context: dict) -> listing_admission.ListingAdmissionCapability:
    """Build a retained admission from an already-materialized (verifier-owned) context.

    Used only for tests that resign a still-authentic Listing chain (for example,
    removing a nonce). The capability still re-verifies the exact bytes and
    signature on every use, so an arbitrary context cannot mint authority.
    """
    listing = context.get("listing")
    agreement = context.get("agreement")
    if not isinstance(listing, dict) or not isinstance(agreement, dict):
        raise ValueError("materialized context has no signed Listing/agreement")
    listing_ref = agreement.get("listingRef")
    publisher = listing.get("seller", {}).get("identity", {}).get("presentedBy")
    if not isinstance(listing_ref, dict) or not isinstance(publisher, str) or not publisher.startswith("key:"):
        raise ValueError("materialized context Listing is invalid")
    inclusion_key = publisher.removeprefix("key:")
    disposition, reason, _ = listing_admission.admit_listing(
        listing,
        inclusion_key=inclusion_key,
        session_boundary=COMMITTED_BOUNDARY,
        native_binding=native_binding(),
    )
    if disposition != "verified":
        raise ValueError("materialized Listing admission did not verify: %r" % ((disposition, reason),))
    return listing_admission.retained_listing_admission(
        listing,
        listing_ref,
        inclusion_key=inclusion_key,
        session_boundary=COMMITTED_BOUNDARY,
        native_binding=native_binding(),
    )
