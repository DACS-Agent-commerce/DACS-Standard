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
    validate_listing_capacity,
)

CORPUS = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "identity-bundle-hash-binding-v0.1.json"
)
CORPUS_SHA256 = "fb144c5fc61787f711debe556768c38281cbc098dd0ed602cb78f1660b9071a5"
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


def _verified_fixture_capability(context: dict) -> listing_admission.ListingAdmissionCapability:
    """Model prior authenticated commitment in this pinned offline harness only.

    The direct bridge deliberately does not authenticate committed-session
    provenance. The existing IBH oracle does so for this test fixture before a
    retained terminal capability is issued; this is not a production adapter.
    """
    import test_identity_bundle_hash_binding_vectors as verifier

    if "commitment" not in context:
        artifact = context.get("artifact")
        if not isinstance(artifact, str):
            raise ValueError("fixture has no commitment artifact")
        context = verifier.materialize(
            {"scenarios": {artifact: context}},
            {"scenario": artifact, "commitment": "finality", "stage": "commit"},
        )

    status, reason, artifact, _ = verifier.dispatch(context)
    if status != "pass" or artifact is None:
        raise ValueError("fixture commitment dispatch did not verify: %r" % ((status, reason),))
    status, reason, _, _ = verifier.pre_action_gate(context, artifact, "commit", set())
    if status != "pass":
        raise ValueError("fixture committed-session gate did not verify: %r" % ((status, reason),))

    listing = context.get("listing")
    agreement = context.get("agreement")
    if not isinstance(listing, dict) or not isinstance(agreement, dict):
        raise ValueError("fixture has no exact Listing/agreement")
    listing_ref = agreement.get("listingRef")
    publisher = listing.get("seller", {}).get("identity", {}).get("presentedBy")
    if not isinstance(listing_ref, dict) or not isinstance(publisher, str) or not publisher.startswith("key:"):
        raise ValueError("fixture Listing publisher or reference is invalid")
    inclusion_key = publisher.removeprefix("key:")
    expected_ref = listing_admission.exact_listing_ref(listing)
    if listing_ref != expected_ref:
        raise ValueError("fixture Listing reference differs from authenticated commitment")
    if validate_listing_capacity(
        listing, native_binding(), substrate=CONFORMANCE_SUBSTRATE,
        finality_profile=CONFORMANCE_FINALITY,
    ) != "pass":
        raise ValueError("fixture native capacity is unavailable")

    retained_context = copy.deepcopy(context)
    retained_listing = copy.deepcopy(listing)
    retained_ref = copy.deepcopy(listing_ref)

    def revalidate(candidate, candidate_ref, boundary):
        if (
            boundary != COMMITTED_BOUNDARY
            or not isinstance(candidate, dict)
            or not isinstance(candidate_ref, dict)
            or listing_admission.canonical_bytes(candidate)
            != listing_admission.canonical_bytes(retained_listing)
            or listing_admission.canonical_bytes(candidate_ref)
            != listing_admission.canonical_bytes(retained_ref)
        ):
            return "rejected", "substituted or stale listing", None
        status, _, selected, _ = verifier.dispatch(retained_context)
        if status != "pass" or selected != artifact:
            return "indeterminate", "prior commitment is unavailable", None
        status, _, _, _ = verifier.pre_action_gate(
            retained_context, artifact, "commit", set()
        )
        if status != "pass":
            return "indeterminate", "prior commitment is unavailable", None
        return "verified", "verified", listing_admission.AdmittedListing(
            "verified", "Listing",
            (retained_ref["listingId"], retained_ref["version"], retained_ref["contentHash"]),
            publisher, inclusion_key, COMMITTED_BOUNDARY,
        )

    return listing_admission.ListingAdmissionCapability(revalidate)


def retained_positive_admission(scenario: str) -> listing_admission.ListingAdmissionCapability:
    """Return a capability from pinned pristine source, before materialization."""
    return _verified_fixture_capability(_scenario_baseline(scenario))


def retained_admission_for_context(context: dict) -> listing_admission.ListingAdmissionCapability:
    """Build a retained admission from an already-materialized (verifier-owned) context.

    Used only for tests that resign a still-authentic Listing chain (for example,
    removing a nonce). The capability still re-verifies the exact bytes and
    signature on every use, so an arbitrary context cannot mint authority.
    """
    return _verified_fixture_capability(context)
