"""Versioned current RSC admission contracts; no production binding is implied."""
from dataclasses import dataclass
from typing import Callable
import jcs

CURRENT_ADMISSION_POLICY = "rsc-current-admission-v2"
RECORDED_ADMISSION_POLICY = "rsc-recorded-admission-v1"
CURRENT_VALUES_POLICY = "rsc-conformance-test-current-values-v2"
CONFORMANCE_SUBSTRATE = "conformance:test"
CONFORMANCE_FINALITY = "rsc-conformance-test-finality-v1"
LISTING_CAP = 16384


@dataclass(frozen=True)
class TrustedNativeRecordBinding:
    """Verifier/producer-installed adapter, never decoded from artifact data.

    encode_record must encode the complete signed artifact and required native
    wrapper. The selected binding owns the encoder, limit, and profile identity.
    No general conversion from canonical bytes to native bytes is defined.
    """
    substrate: str
    finality_profile: str
    encoding_policy: str
    record_limit: int
    encode_record: Callable[[dict], bytes]
    canonical_budget: int | None = None


def listing_content_size(listing: dict) -> int:
    if not isinstance(listing, dict):
        raise ValueError("Listing must be an object")
    return len(jcs.canonicalize({k: v for k, v in listing.items() if k != "signature"}).encode("utf-8"))


def validate_listing_capacity(listing: dict, binding, *, substrate: str,
                              finality_profile: str) -> str:
    """Shared producer/reader check: pass, fail, or unsupported indeterminate."""
    try:
        size = listing_content_size(listing)
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        return "fail"
    if size > LISTING_CAP:
        return "fail"
    if not isinstance(binding, TrustedNativeRecordBinding):
        return "indeterminate"
    if (binding.substrate != substrate or binding.finality_profile != finality_profile
            or not isinstance(binding.encoding_policy, str) or not binding.encoding_policy
            or type(binding.record_limit) is not int or binding.record_limit <= 0
            or not callable(binding.encode_record)):
        return "indeterminate"
    if binding.canonical_budget is not None:
        if type(binding.canonical_budget) is not int or binding.canonical_budget <= 0:
            return "indeterminate"
        if size > min(LISTING_CAP, binding.canonical_budget):
            return "fail"
    try:
        import copy
        encoded = binding.encode_record(copy.deepcopy(listing))
    except Exception:
        # A provider failure cannot turn missing native-size evidence into pass.
        return "indeterminate"
    if not isinstance(encoded, bytes):
        return "indeterminate"
    return "pass" if len(encoded) <= binding.record_limit else "fail"


def joined_current_state(listing_evidence, revocation_evidence, trusted) -> bool:
    """Join already signature-verified values under the pinned fixture policy.

    The state identifier and authority are verifier-installed for this decision;
    equal producer labels or two ordinary reads cannot establish currentness.
    """
    if trusted.get("admissionPolicy") != CURRENT_ADMISSION_POLICY:
        return False
    state = trusted.get("evaluationState")
    if not isinstance(state, dict) or set(state) != {"policy", "finalizedStateId", "substrate", "finalityProfile"}:
        return False
    if (state["policy"] != CURRENT_VALUES_POLICY
            or state["substrate"] != CONFORMANCE_SUBSTRATE
            or state["finalityProfile"] != CONFORMANCE_FINALITY
            or not isinstance(state["finalizedStateId"], str) or not state["finalizedStateId"]):
        return False
    return all(isinstance(e, dict) and e.get("policy") == state["policy"]
               and e.get("finalizedStateId") == state["finalizedStateId"]
               for e in (listing_evidence, revocation_evidence))
