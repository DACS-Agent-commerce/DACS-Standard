"""Shared structural dispatch for DACS-1 ListingArtifact test consumers.

This is deliberately a syntax/dispatch helper, not a complete DACS validator.
Callers still verify identity, signatures, revocation, rails, and phase-specific
semantics. Unknown extension members are retained in the signed/hash input.
"""

from __future__ import annotations

import math
import re

try:
    from jcs import canonicalize as jcs_canonicalize
except ImportError:  # imported as scripts.listing_artifact by tests
    from scripts.jcs import canonicalize as jcs_canonicalize


LEGACY_LISTING = "Listing"
REVOCATION_BOUND_LISTING = "RevocationBoundListing"
LISTING_DOMAINS = {
    LEGACY_LISTING: "dacs-listing:v1:",
    REVOCATION_BOUND_LISTING: "dacs-revocation-bound-listing:v1:",
}

KNOWN_PHASES = frozenset({
    "vet-credentials",
    "negotiate-fixed-price",
    "negotiate-rfq",
    "negotiate-sealed-envelope",
    "negotiate-sealed-envelope-procurement",
    "negotiate-sealed-envelope-complete",
    "negotiate-sealed-envelope-procurement-complete",
    "commit-agreement",
    "commit-payee-bound-agreement",
    "commit-identity-bound-agreement",
    "commit-identity-bound-payee-agreement",
    "commit-selection-bound-agreement",
    "pay-evm-erc20",
    "pay-solana-spl",
    "pay-cross-chain-htlc",
    "pay-cross-chain-liquidity-tank",
    "pay-ap2",
    "pay-x402",
    "pay-dem",
    "pay-alternative",
    "deliver-storage-program",
    "deliver-entitlement",
    "deliver-attested-payload",
    "rate",
})
CONCRETE_PAYMENT_PHASES = frozenset(
    phase for phase in KNOWN_PHASES if phase.startswith("pay-")
) - {"pay-alternative"}
DELIVERY_PHASES = frozenset(
    phase for phase in KNOWN_PHASES if phase.startswith("deliver-")
)
NEGOTIATION_PHASES = frozenset(
    phase for phase in KNOWN_PHASES if phase.startswith("negotiate-")
)
COMMITMENT_PHASES = frozenset({
    "commit-agreement", "commit-payee-bound-agreement",
    "commit-identity-bound-agreement", "commit-identity-bound-payee-agreement",
    "commit-selection-bound-agreement",
})
COMPLETE_SEALED_NEGOTIATIONS = frozenset({
    "negotiate-sealed-envelope-complete",
    "negotiate-sealed-envelope-procurement-complete",
})

_LISTING_ID = re.compile(r"[A-Za-z0-9._~-]{1,128}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_AMOUNT = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?\Z")
_SELECTION_RULES = frozenset({"lowest-price", "highest-price", "first-acceptable"})
_CAPABILITIES = frozenset({"SR-1", "SR-2", "SR-3", "SR-4", "SR-5"})
_SAFE_INTEGER_MAX = 2**53 - 1


def classify_listing_artifact(listing, supported=None):
    """Return ``(type, domain)`` or raise ValueError before type-specific use."""
    if not isinstance(listing, dict):
        raise ValueError("listing is not an object")
    has_legacy = "dacsVersion" in listing
    has_bound = "revocationBoundListingVersion" in listing
    if has_legacy == has_bound:
        raise ValueError("listing discriminator is missing or non-exclusive")
    artifact_type = LEGACY_LISTING if has_legacy else REVOCATION_BOUND_LISTING
    discriminator = "dacsVersion" if has_legacy else "revocationBoundListingVersion"
    if listing.get(discriminator) != "1":
        raise ValueError("listing type version is unsupported")
    if supported is not None and artifact_type not in supported:
        raise ValueError("listing type is unsupported by this consumer")
    return artifact_type, LISTING_DOMAINS[artifact_type]


def _is_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and abs(value) <= _SAFE_INTEGER_MAX
        and math.isfinite(value)
    )


def _valid_hash_bound_json(listing):
    """Check the complete CORE §B.2 Listing input without changing its bytes."""
    unsigned = {key: value for key, value in listing.items() if key != "signature"}
    try:
        jcs_canonicalize(unsigned)
    except (OverflowError, TypeError, ValueError):
        return False
    return True


def validate_sealed_session_deadline(listing, session_start):
    """Apply SE-1 only when admitting a new session, not historical reads."""
    try:
        pipeline = listing.get("pipeline") if isinstance(listing, dict) else None
        if not isinstance(pipeline, list):
            return False, "invalid pipeline"
        for step in pipeline:
            if not isinstance(step, dict):
                return False, "invalid pipeline"
            if step.get("kind") not in {
                "negotiate-sealed-envelope",
                "negotiate-sealed-envelope-procurement",
                *COMPLETE_SEALED_NEGOTIATIONS,
            }:
                continue
            if not _is_number(session_start):
                return False, "invalid session start"
            parameters = step.get("parameters")
            deadline = parameters.get("commitDeadline") if isinstance(parameters, dict) else None
            if not _is_number(deadline) or deadline < session_start + 60_000:
                return False, "sealed commit deadline is too early"
        return True, None
    except (OverflowError, TypeError, ValueError):
        return False, "invalid sealed session time"


def validate_listing_window(listing, now):
    """Validate a Listing validity window at one verifier-trusted instant.

    This check is separate from structural validation so historical publication
    and lineage readers can validate retained bytes without applying a fresh
    new-session clock.  New-session admission callers must supply a finite,
    non-boolean numeric value from verifier-local state.
    """
    if not _is_number(now):
        return False, "invalid listing evaluation time"
    validity = listing.get("validity") if isinstance(listing, dict) else None
    if (
        not isinstance(validity, dict)
        or not _is_number(validity.get("notBefore"))
        or ("notAfter" in validity and not _is_number(validity["notAfter"]))
        or ("notAfter" in validity and validity["notAfter"] < validity["notBefore"])
    ):
        return False, "invalid validity"
    if (
        now < validity["notBefore"]
        or ("notAfter" in validity and now > validity["notAfter"])
    ):
        return False, "listing outside validity window"
    return True, None


def _is_nonempty_string(value):
    return isinstance(value, str) and bool(value)


def _valid_attestation_ref(value):
    if not isinstance(value, dict) or not {"anchor", "contentHash"} <= set(value):
        return False
    if set(value) - {"anchor", "contentHash", "signer"}:
        return False
    anchor = value["anchor"]
    return (
        isinstance(anchor, dict)
        and set(anchor) == {"kind", "locator"}
        and isinstance(anchor["kind"], str)
        and anchor["kind"] in {"storage-program", "ipfs", "https"}
        and _is_nonempty_string(anchor["locator"])
        and isinstance(value["contentHash"], str)
        and _HASH.fullmatch(value["contentHash"]) is not None
        and ("signer" not in value or _is_nonempty_string(value["signer"]))
    )


def _valid_price(value):
    return (
        isinstance(value, dict)
        and _is_nonempty_string(value.get("amount"))
        and _AMOUNT.fullmatch(value["amount"]) is not None
        and value["amount"] != "0"
        and _is_nonempty_string(value.get("currency"))
        and ("unit" not in value or _is_nonempty_string(value["unit"]))
    )


def _valid_pricing(value):
    if not isinstance(value, dict):
        return False
    kind = value.get("kind")
    if kind == "fixed":
        return _valid_price(value.get("price"))
    if kind == "negotiable":
        return (
            _valid_price(value.get("bandCenter"))
            and _is_number(value.get("minPct"))
            and _is_number(value.get("maxPct"))
            and 0 <= value["minPct"] < 100
            and value["maxPct"] >= 0
        )
    if kind == "auction":
        selection = value.get("selectionRule")
        return (
            _is_nonempty_string(selection)
            and (selection in _SELECTION_RULES or selection.startswith("rule-ref:"))
            and ("reservePrice" not in value or _valid_price(value["reservePrice"]))
        )
    if kind == "metered":
        return (
            _valid_price(value.get("unitPrice"))
            and _is_nonempty_string(value.get("unit"))
            and ("minTotal" not in value or _valid_price(value["minTotal"]))
        )
    return False


def _valid_deliverable(value):
    if not isinstance(value, dict):
        return False
    kind = value.get("kind")
    if kind == "storage-program":
        return True
    if kind == "entitlement":
        return _is_number(value.get("durationSec")) and isinstance(value.get("renewable"), bool)
    if kind == "attested-payload":
        return _is_nonempty_string(value.get("payloadFormat"))
    if kind == "external":
        return _is_nonempty_string(value.get("description"))
    return False


def _valid_claim_requirement(value):
    if (
        not isinstance(value, dict)
        or not _is_nonempty_string(value.get("scheme"))
        or not isinstance(value.get("verificationRequired"), bool)
        or ("parameters" in value and not isinstance(value["parameters"], dict))
    ):
        return False
    if value["verificationRequired"]:
        return (
            ("maxAge" not in value or _is_number(value["maxAge"]))
            and (
                "recipeVersion" not in value
                or isinstance(value["recipeVersion"], int)
                and not isinstance(value["recipeVersion"], bool)
                and value["recipeVersion"] > 0
            )
        )
    return "maxAge" not in value and "recipeVersion" not in value


def _valid_bundle_requirement(value):
    if (
        not isinstance(value, dict)
        or value.get("requirementVersion") != "1"
        or not isinstance(value.get("required"), list)
        or not all(_valid_claim_requirement(item) for item in value["required"])
    ):
        return False
    groups = value.get("oneOf", [])
    return (
        isinstance(groups, list)
        and all(
            isinstance(group, list)
            and bool(group)
            and all(_valid_claim_requirement(item) for item in group)
            for group in groups
        )
    )


def _valid_pipeline(pipeline, pricing, deliverable):
    if (
        not isinstance(pipeline, list)
        or not pipeline
        or any(
            not isinstance(step, dict)
            or step.get("kind") not in KNOWN_PHASES
            or ("parameters" in step and not isinstance(step["parameters"], dict))
            for step in pipeline
        )
    ):
        return False
    kinds = [step["kind"] for step in pipeline]
    negotiations = [index for index, kind in enumerate(kinds) if kind in NEGOTIATION_PHASES]
    commitments = [index for index, kind in enumerate(kinds) if kind in COMMITMENT_PHASES]
    if (
        len(negotiations) != 1
        or len(commitments) != 1
        or commitments[0] != negotiations[0] + 1
        or not any(kind in DELIVERY_PHASES for kind in kinds)
    ):
        return False
    negotiation = kinds[negotiations[0]]
    pricing_kind = pricing.get("kind")
    if (
        negotiation == "negotiate-fixed-price"
        and pricing_kind not in {"fixed", "negotiable", "metered"}
        or negotiation == "negotiate-rfq"
        and pricing_kind not in {"negotiable", "metered"}
        or negotiation in {
            "negotiate-sealed-envelope", "negotiate-sealed-envelope-procurement"
        } | COMPLETE_SEALED_NEGOTIATIONS
        and pricing_kind != "auction"
    ):
        return False
    step = pipeline[negotiations[0]]
    parameters = step.get("parameters")
    if negotiation == "negotiate-rfq" and (
        not isinstance(parameters, dict)
        or not _is_number(parameters.get("maxTurns"))
        or parameters["maxTurns"] < 2
        or not _is_number(parameters.get("timeoutSec"))
    ):
        return False
    if (
        (negotiation in COMPLETE_SEALED_NEGOTIATIONS)
        != (kinds[commitments[0]] == "commit-selection-bound-agreement")
    ):
        return False
    if negotiation.startswith("negotiate-sealed-envelope") and (
        not isinstance(parameters, dict)
        or not _is_number(parameters.get("commitDeadline"))
        or not _is_number(parameters.get("revealWindow"))
        or parameters["revealWindow"] < 60
        or parameters.get("selectionRule") != pricing.get("selectionRule")
        or negotiation in {
            "negotiate-sealed-envelope-procurement",
            "negotiate-sealed-envelope-procurement-complete",
        }
        and parameters.get("auctionMode") != "procurement"
        or negotiation in {
            "negotiate-sealed-envelope",
            "negotiate-sealed-envelope-complete",
        }
        and "auctionMode" in parameters and parameters["auctionMode"] != "demand"
        or negotiation in COMPLETE_SEALED_NEGOTIATIONS
        and (
            parameters.get("selectionRule") not in {"lowest-price", "highest-price"}
            or not isinstance(parameters.get("candidateSetBinding"), dict)
            or set(parameters["candidateSetBinding"]) != {
                "bindingId", "bindingVersion", "definitionRef"
            }
            or not _is_nonempty_string(parameters["candidateSetBinding"].get("bindingId"))
            or not isinstance(parameters["candidateSetBinding"].get("bindingVersion"), str)
            or re.fullmatch(r"[1-9][0-9]*", parameters["candidateSetBinding"]["bindingVersion"]) is None
            or not _valid_attestation_ref(parameters["candidateSetBinding"].get("definitionRef"))
        )
    ):
        return False
    alternatives = [step for step in pipeline if step["kind"] == "pay-alternative"]
    concrete = [step for step in pipeline if step["kind"] in CONCRETE_PAYMENT_PHASES]
    if alternatives:
        refs = alternatives[0].get("parameters", {}).get("alternatives")
        if (
            len(alternatives) != 1
            or concrete
            or not isinstance(refs, list)
            or len(refs) < 2
            or any(not isinstance(ref, dict) or not _is_nonempty_string(ref.get("railId")) for ref in refs)
        ):
            return False
    if any(
        not isinstance(step.get("parameters"), dict)
        or not _is_nonempty_string(step["parameters"].get("rail"))
        for step in concrete
    ):
        return False
    if "deliver-attested-payload" in kinds and (
        deliverable.get("kind") != "attested-payload"
        or not isinstance(deliverable.get("verificationMethod"), dict)
    ):
        return False
    return True


def validate_listing_shape(listing, *, now=None, supported=None):
    """Validate the complete required outer shape and closed executable unions.

    Optional fields stay optional. Unknown members are not projected away: the
    caller must hash and verify the original object, including those members.
    """
    try:
        artifact_type, domain = classify_listing_artifact(listing, supported)
    except ValueError as exc:
        return False, str(exc), None, None

    if not _valid_hash_bound_json(listing):
        return False, "listing is not canonicalizable under CORE profile", artifact_type, domain

    if (
        not isinstance(listing.get("listingVersion"), int)
        or isinstance(listing.get("listingVersion"), bool)
        or listing["listingVersion"] < 1
        or listing["listingVersion"] > _SAFE_INTEGER_MAX
        or not isinstance(listing.get("listingId"), str)
        or _LISTING_ID.fullmatch(listing["listingId"]) is None
    ):
        return False, "invalid listing identity", artifact_type, domain
    capabilities = listing.get("requiredCapabilities")
    if capabilities is not None and (
        not isinstance(capabilities, list)
        or any(item not in _CAPABILITIES for item in capabilities)
    ):
        return False, "invalid requiredCapabilities", artifact_type, domain

    seller = listing.get("seller")
    if (
        not isinstance(seller, dict)
        or not isinstance(seller.get("identity"), dict)
        or not _is_nonempty_string(seller.get("displayName"))
        or ("publicEndpoint" in seller and not _is_nonempty_string(seller["publicEndpoint"]))
    ):
        return False, "invalid seller", artifact_type, domain

    offering = listing.get("offering")
    if (
        not isinstance(offering, dict)
        or not _is_nonempty_string(offering.get("title"))
        or not isinstance(offering.get("description"), str)
        or not _is_nonempty_string(offering.get("category"))
        or not isinstance(offering.get("tags"), list)
        or any(not isinstance(tag, str) for tag in offering["tags"])
        or not _valid_deliverable(offering.get("deliverable"))
    ):
        return False, "invalid offering", artifact_type, domain

    if not _valid_bundle_requirement(listing.get("buyerRequirement")):
        return False, "invalid buyerRequirement", artifact_type, domain
    if not isinstance(listing.get("terms"), dict):
        return False, "invalid terms", artifact_type, domain
    if not _valid_pricing(listing.get("pricing")):
        return False, "invalid pricing", artifact_type, domain

    validity = listing.get("validity")
    if (
        not isinstance(validity, dict)
        or not _is_number(validity.get("notBefore"))
        or ("notAfter" in validity and not _is_number(validity["notAfter"]))
        or ("notAfter" in validity and validity["notAfter"] < validity["notBefore"])
    ):
        return False, "invalid validity", artifact_type, domain
    if now is not None:
        window_ok, window_reason = validate_listing_window(listing, now)
        if not window_ok:
            return False, window_reason, artifact_type, domain

    pipeline = listing.get("pipeline")
    if not _valid_pipeline(pipeline, listing["pricing"], offering["deliverable"]):
        return False, "invalid or unsupported pipeline", artifact_type, domain

    accepted = listing.get("acceptedRails")
    if accepted is not None and (
        not isinstance(accepted, list)
        or any(not isinstance(ref, dict) or not _is_nonempty_string(ref.get("railId")) for ref in accepted)
    ):
        return False, "invalid acceptedRails", artifact_type, domain
    if any(step["kind"] in CONCRETE_PAYMENT_PHASES or step["kind"] == "pay-alternative" for step in pipeline):
        if not isinstance(accepted, list) or not accepted:
            return False, "payment pipeline requires acceptedRails", artifact_type, domain

    if artifact_type == REVOCATION_BOUND_LISTING and not isinstance(listing.get("revocationState"), dict):
        return False, "revocation-bound listing lacks revocationState", artifact_type, domain
    signature = listing.get("signature")
    if (
        not isinstance(signature, dict)
        or not _is_nonempty_string(signature.get("algorithm"))
        or not _is_nonempty_string(signature.get("signer"))
        or not _is_nonempty_string(signature.get("value"))
    ):
        return False, "invalid listing signature shape", artifact_type, domain
    return True, None, artifact_type, domain


def prepare_listing_publication(listing, binding, *, substrate, finality_profile):
    """Validate a complete signed Listing before the caller invokes native write.

    This current publication boundary is separate from historical shape checking.
    Only pass returns a capacity-checked artifact. The publisher still owns
    signature/authority validation and all other publication requirements.
    No provider call, signature repair, or canonical/native conversion occurs here.
    """
    import copy
    from rsc_current_admission import validate_listing_capacity
    candidate = copy.deepcopy(listing)
    if not validate_listing_shape(candidate)[0]:
        return "fail", None
    disposition = validate_listing_capacity(candidate, binding, substrate=substrate,
                                             finality_profile=finality_profile)
    return disposition, candidate if disposition == "pass" else None
