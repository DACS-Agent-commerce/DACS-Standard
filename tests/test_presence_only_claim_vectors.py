import base64
import copy
import hashlib
import json
import re
import subprocess
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import validate_conformance_vectors as vcv  # noqa: E402
from dacs_reference import (  # noqa: E402
    SAFE_INTEGER,
    NonceLedger,
    NonceRejected,
    exact_safe_integer,
    finite_safe_number,
    parse_claim_reference,
    presentation_nonce,
)

VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "presence-only-claim-requirement-v0.7.json"
)
GENERATOR = ROOT / "scripts" / "generate_presence_only_claim_vectors.py"
DACS1 = ROOT / "spec" / "DACS-1-IDENTIFY.md"
DACS2 = ROOT / "spec" / "DACS-2-VET.md"
CONTROL_FIXTURE = (
    ROOT / "conformance" / "fixtures" / "identity"
    / "dacs1-vet-golden-inputs-v0.1.json"
)
BUNDLE_DOMAIN = "dacs-bundle-presentation:v1:"
VERIFY_RESULT_DOMAIN = "dacs-verifyresult:v1:"
COMPOSITE_DOMAIN = "dacs-composite:v1:"
KNOWN_SCHEMES = {"key", "lei", "did"}


def canonical_bytes(value):
    return vcv.canonical_json(value)


def hash_hex(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def canonical_equal(left, right):
    return canonical_bytes(left) == canonical_bytes(right)


def signed_component_hash(value):
    return vcv.artifact_hash_hex("VerifyResult", value)


def b64url_decode(value):
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("non-canonical Base64URL")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError("non-canonical Base64URL")
    return decoded


def parse_ref(value):
    return parse_claim_reference(
        value, registered_schemes=KNOWN_SCHEMES
    ).identity


def well_formed_result_ref(value):
    if not isinstance(value, dict) or set(value) != {
        "anchor", "contentHash", "recipeVersion"
    }:
        return False
    anchor = value.get("anchor")
    return (
        isinstance(anchor, dict)
        and set(anchor) == {"kind", "locator"}
        and isinstance(anchor.get("kind"), str)
        and anchor.get("kind") in {"storage-program", "ipfs", "https"}
        and isinstance(anchor.get("locator"), str)
        and bool(anchor["locator"])
        and isinstance(value.get("contentHash"), str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", value["contentHash"]))
        and exact_safe_integer(value.get("recipeVersion"), minimum=1)
    )


def verify_component(artifact, domain, expected_signer):
    if not isinstance(artifact, dict):
        return False
    signature = artifact.get("signature")
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm", "signer", "value"
    }:
        return False
    if signature.get("algorithm") != "ed25519":
        return False
    if signature.get("signer") != expected_signer:
        return False
    try:
        scheme, public_hex = parse_ref(signature.get("signer"))
        if scheme != "key":
            return False
        unsigned = {key: value for key, value in artifact.items() if key != "signature"}
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            b64url_decode(signature.get("value")),
            (domain + hash_hex(unsigned)).encode("ascii"),
        )
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def trusted_context_valid(value):
    if not isinstance(value, dict) or set(value) != {
        "compositeSigner", "verifyResultAuthorities", "vetInvocations",
        "nonceIssuances", "recipeRegistryVersion", "authenticatedSessionStarts",
    }:
        return False
    try:
        composite_scheme, _ = parse_ref(value["compositeSigner"])
    except ValueError:
        return False
    if composite_scheme != "key":
        return False
    if not exact_safe_integer(value.get("recipeRegistryVersion"), minimum=1):
        return False
    if not isinstance(value.get("authenticatedSessionStarts"), dict):
        return False
    authorities = value["verifyResultAuthorities"]
    if not isinstance(authorities, list):
        return False
    seen = set()
    for authority in authorities:
        if not isinstance(authority, dict) or set(authority) != {
            "scheme", "method", "recipeVersion", "signer",
            "defaultMaxAgeSec", "availability",
        }:
            return False
        family = (
            authority.get("scheme"),
            authority.get("method"),
            authority.get("recipeVersion"),
        )
        try:
            signer_scheme, _ = parse_ref(authority.get("signer"))
        except ValueError:
            return False
        if (
            not isinstance(authority.get("scheme"), str)
            or authority.get("scheme") not in KNOWN_SCHEMES
            or not isinstance(authority.get("method"), str)
            or not authority["method"]
            or not exact_safe_integer(
                authority.get("recipeVersion"), minimum=1
            )
            or not exact_safe_integer(
                authority.get("defaultMaxAgeSec"), minimum=0
            )
            or authority.get("availability") != "live"
            or signer_scheme != "key"
            or family in seen
        ):
            return False
        seen.add(family)
    return isinstance(value.get("vetInvocations"), dict) and isinstance(
        value.get("nonceIssuances"), list
    )


@dataclass(frozen=True)
class VetAdmission:
    invocation_id: str
    challenge_id: str
    nonce: str
    job_id: str
    actor: str
    evaluated_party: str
    phase_index: int
    attempt: int
    expected_verifier_role: str
    expected_verifier: str
    phase_orchestrator: str
    trusted_now: int
    challenge_issued_at: int
    registry_available: bool
    registry_authenticated: bool
    bundle_available: bool
    requirement_hash: str
    bundle_input_hash: str


@dataclass(frozen=True)
class UnavailableBundleDiagnostic:
    """Non-authorizing CVR context; it never consumes or projects a nonce."""

    expected_verifier: str
    job_id: str
    evaluated_party: str
    trusted_now: int
    requirement_hash: str
    registry_available: bool
    registry_authenticated: bool
    bundle_available: bool = False


class PresenceEvaluationRuntime:
    """Retained verifier state for active aggregate admission."""

    _INVOCATION_FIELDS = {
        "jobId", "sessionState", "phaseKind", "phaseIndex", "attempt",
        "actor", "evaluatedParty", "expectedVerifierRole",
        "expectedVerifier", "phaseOrchestrator", "challengeId", "trustedNow",
        "registryAvailable", "registryAuthenticated", "bundleAvailable",
        "sessionContext", "recipeRegistryVersion", "requirementHash", "bundleInputHash",
    }

    def __init__(self, trusted_context):
        if not trusted_context_valid(trusted_context):
            raise ValueError("trusted Vet context is invalid")
        self.trusted_context = trusted_context
        self.invocations = trusted_context["vetInvocations"]
        self.nonce_ledger = NonceLedger(trusted_context["nonceIssuances"])

    def _trusted_invocation(self, invocation_id):
        context = self.invocations.get(invocation_id)
        if not isinstance(context, dict) or set(context) != self._INVOCATION_FIELDS:
            return None
        session = context.get("sessionContext")
        if (
            not isinstance(session, dict)
            or set(session) != {"jobId", "recipeRegistryVersion"}
            or not isinstance(context.get("jobId"), str)
            or session != self.trusted_context["authenticatedSessionStarts"].get(context.get("jobId"))
            or session.get("jobId") != context.get("jobId")
            or not exact_safe_integer(session.get("recipeRegistryVersion"), minimum=1)
            or not exact_safe_integer(context.get("recipeRegistryVersion"), minimum=1)
            or session["recipeRegistryVersion"] != context["recipeRegistryVersion"]
            or context["recipeRegistryVersion"] != self.trusted_context["recipeRegistryVersion"]
            or any(
                not isinstance(context.get(field), str)
                or re.fullmatch(r"[0-9a-f]{64}", context[field]) is None
                for field in ("requirementHash", "bundleInputHash")
            )
        ):
            return None
        if (
            context.get("sessionState") != "vet-pending"
            or context.get("phaseKind") != "vet-credentials"
            or not isinstance(context.get("actor"), str)
            or context.get("actor") not in {"buyer", "seller"}
            or not isinstance(context.get("expectedVerifierRole"), str)
            or context.get("expectedVerifierRole")
            not in {"counterparty", "orchestrator"}
            or not exact_safe_integer(context.get("phaseIndex"), minimum=0)
            or not exact_safe_integer(context.get("attempt"), minimum=1)
            or not exact_safe_integer(context.get("trustedNow"), minimum=0)
            or type(context.get("registryAvailable")) is not bool
            or type(context.get("registryAuthenticated")) is not bool
            or type(context.get("bundleAvailable")) is not bool
            or not isinstance(context.get("challengeId"), str)
        ):
            return None
        try:
            for field in (
                "evaluatedParty", "expectedVerifier", "phaseOrchestrator"
            ):
                parse_ref(context.get(field))
        except ValueError:
            return None
        if (
            context["expectedVerifierRole"] == "orchestrator"
            and context["expectedVerifier"] != context["phaseOrchestrator"]
        ):
            return None
        return context

    def admit(self, authority, bundle):
        if (
            not isinstance(authority, dict)
            or set(authority) != {"kind", "invocation", "nonce"}
            or authority.get("kind") != "vet-invocation"
        ):
            return None
        invocation_id = authority.get("invocation")
        if not isinstance(invocation_id, str):
            return None
        context = self._trusted_invocation(invocation_id)
        if context is None:
            return None
        try:
            # SN-4 consumes the nonce conveyed by the candidate presentation,
            # not a caller-projected copy in its invocation wrapper.
            issuance = self.nonce_ledger.consume(
                context["challengeId"], presentation_nonce(bundle),
                context["trustedNow"],
            )
        except NonceRejected:
            return None
        if (
            authority.get("nonce") != issuance.nonce
            or issuance.job_id != context["jobId"]
            or issuance.actor != context["actor"]
            or issuance.evaluated_party != context["evaluatedParty"]
            or issuance.phase_index != context["phaseIndex"]
            or issuance.attempt != context["attempt"]
            or issuance.expected_verifier != context["expectedVerifier"]
            or issuance.issued_by != context["expectedVerifier"]
        ):
            return None
        return VetAdmission(
            invocation_id,
            context["challengeId"],
            issuance.nonce,
            context["jobId"],
            context["actor"],
            context["evaluatedParty"],
            context["phaseIndex"],
            context["attempt"],
            context["expectedVerifierRole"],
            context["expectedVerifier"],
            context["phaseOrchestrator"],
            context["trustedNow"],
            issuance.issued_at,
            context["registryAvailable"],
            context["registryAuthenticated"],
            context["bundleAvailable"],
            context["requirementHash"],
            context["bundleInputHash"],
        )


def expected_result_signer(context, result):
    matches = [
        authority
        for authority in context["verifyResultAuthorities"]
        if authority["scheme"] == result.get("scheme")
        and authority["method"] == result.get("method")
        and authority["recipeVersion"] == result.get("recipeVersion")
    ]
    return matches[0]["signer"] if len(matches) == 1 else None


def verify_bundle(bundle, admission=None):
    if not isinstance(bundle, dict):
        return False
    if not {"bundleVersion", "presentedBy", "presentedAt", "claims", "presentation"} <= set(bundle):
        return False
    if (
        bundle.get("bundleVersion") != "1"
        or not finite_safe_number(bundle.get("presentedAt"))
        or not isinstance(bundle.get("claims"), list)
        or not bundle["claims"]
        or (admission is not None and presentation_nonce(bundle) != admission.nonce)
    ):
        return False
    try:
        # Exact presenter resolution is an aggregation predicate.  Structural
        # bundle verification only requires a well-formed presentedBy plus
        # valid signatures from included claims.
        parse_claim_reference(
            bundle.get("presentedBy"), registered_schemes=KNOWN_SCHEMES
        )
        parsed_claims = [
            parse_claim_reference(
                item.get("ref"), registered_schemes=KNOWN_SCHEMES
            )
            for item in bundle["claims"] if isinstance(item, dict)
        ]
    except (AttributeError, ValueError):
        return False
    if len(parsed_claims) != len(bundle["claims"]):
        return False
    presentation = bundle.get("presentation")
    if (
        not isinstance(presentation, dict)
        or set(presentation) != {"kind", "signatures"}
        or presentation.get("kind") != "per-claim"
    ):
        return False
    signatures = presentation.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return False
    unsigned = {key: value for key, value in bundle.items() if key != "presentation"}
    try:
        payload = (BUNDLE_DOMAIN + hash_hex(unsigned)).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        return False
    claim_identities = {parsed.identity for parsed in parsed_claims}
    for signature in signatures:
        if not isinstance(signature, dict) or set(signature) != {"ref", "signature"}:
            return False
        try:
            parsed_signer = parse_claim_reference(
                signature["ref"], registered_schemes=KNOWN_SCHEMES
            )
            scheme, public_hex = parsed_signer.identity
            if scheme != "key" or parsed_signer.identity not in claim_identities:
                return False
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
                b64url_decode(signature["signature"]), payload
            )
        except (InvalidSignature, TypeError, ValueError):
            return False
    return True


def all_members(requirement):
    yield from requirement.get("required", [])
    for group in requirement.get("oneOf", []):
        yield from group


def presence_parameters_match(claim, requirement):
    parameters = requirement.get("parameters")
    if parameters is None:
        return True
    metadata = claim.get("metadata")
    return isinstance(metadata, dict) and all(
        key in metadata and canonical_equal(metadata[key], required)
        for key, required in parameters.items()
    )


def verified_parameters_match(result, requirement):
    parameters = requirement.get("parameters")
    if parameters is None:
        return True
    method = parameters.get("verificationMethod")
    if method is not None and result.get("method") != method:
        return False
    required_data = {
        key: value for key, value in parameters.items()
        if key != "verificationMethod"
    }
    if not required_data:
        return True
    data = result.get("data")
    return isinstance(data, dict) and all(
        key in data and canonical_equal(data[key], required)
        for key, required in required_data.items()
    )


def canonical_claims(bundle):
    claims = []
    for claim in bundle.get("claims", []):
        if not isinstance(claim, dict):
            raise ValueError("claim must be an object")
        parsed = parse_claim_reference(
            claim.get("ref"), registered_schemes=KNOWN_SCHEMES
        )
        for field in ("issuedAt", "expiresAt"):
            if field in claim and not finite_safe_number(claim.get(field)):
                raise ValueError(f"claim {field} must be a finite safe number")
        claims.append((claim, parsed))
    return claims


def exact_presented_claim(bundle, claims):
    """Resolve one canonical-distinct BundleClaim by CF-3 identity.

    Repeated byte-identical claim values collapse to one candidate. Distinct
    signed claim values with the same CF-3 identity are ambiguous and resolve
    no presenter, independent of their array order.
    """

    try:
        presented = parse_claim_reference(
            bundle.get("presentedBy"), registered_schemes=KNOWN_SCHEMES
        )
        distinct = {
            canonical_bytes(claim): (claim, parsed)
            for claim, parsed in claims
            if parsed.identity == presented.identity
        }
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return None
    return next(iter(distinct.values())) if len(distinct) == 1 else None


def exact_presenter_key_controlled(vector, claims):
    """Verify this pack's exact per-claim key presenter control proof."""

    bundle = vector["bundle"]
    resolved = exact_presented_claim(bundle, claims)
    if resolved is None:
        return False
    _, presented = resolved
    if presented.scheme != "key":
        return False
    unsigned = {key: value for key, value in bundle.items() if key != "presentation"}
    try:
        payload = (BUNDLE_DOMAIN + hash_hex(unsigned)).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        return False
    for signature in bundle["presentation"].get("signatures", []):
        try:
            signer = parse_claim_reference(
                signature.get("ref"), registered_schemes=KNOWN_SCHEMES
            )
            if signer.identity != presented.identity or signer.scheme != "key":
                continue
            Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(signer.identifier)
            ).verify(b64url_decode(signature.get("signature")), payload)
            return True
        except (AttributeError, InvalidSignature, TypeError, ValueError):
            continue
    return False


def matching_claims(
    claims, requirement, decision_time, *, presence_predicate, exact_ref=None
):
    exact = None
    if exact_ref is not None:
        exact = parse_claim_reference(
            exact_ref, registered_schemes=KNOWN_SCHEMES
        ).identity
    matches = []
    for claim, parsed in claims:
        if parsed.scheme != requirement.get("scheme"):
            continue
        if exact is not None and parsed.identity != exact:
            continue
        expires_at = claim.get("expiresAt")
        if expires_at is not None and decision_time > expires_at:
            continue
        if presence_predicate and not presence_parameters_match(claim, requirement):
            continue
        matches.append((claim, parsed))
    return matches


def valid_composite_shape(record):
    required = {
        "recordVersion", "jobId", "evaluatedParty", "bundleHash", "requirementHash",
        "freshness", "supplementary", "dealSpecific", "overallDecision", "generatedAt", "signature",
    }
    return (
        isinstance(record, dict)
        and required <= set(record)
        and record.get("recordVersion") == "1"
        and all(isinstance(record.get(field), list) for field in (
            "freshness", "supplementary", "dealSpecific",
        ))
        and ("warnings" not in record or isinstance(record["warnings"], list))
    )


def record_refs(record):
    freshness = record.get("freshness")
    deal_specific = record.get("dealSpecific")
    if not isinstance(freshness, list) or not isinstance(deal_specific, list):
        raise ValueError("record result collections must be arrays")
    return [*freshness, *deal_specific]


def bind_resolved_results(vector, record):
    committed = record_refs(record)
    if any(not well_formed_result_ref(reference) for reference in committed):
        raise ValueError("committed result reference is malformed")
    resolved = vector.get("resolvedResults")
    if not isinstance(resolved, list):
        raise ValueError("resolved result projection must be an array")
    if any(
        not isinstance(item, dict)
        or set(item) != {"ref", "artifact"}
        or not well_formed_result_ref(item.get("ref"))
        for item in resolved
    ):
        raise ValueError("resolved result entry is malformed")
    committed_keys = [canonical_bytes(reference) for reference in committed]
    resolved_keys = [canonical_bytes(item["ref"]) for item in resolved]
    if (
        len(set(committed_keys)) != len(committed_keys)
        or resolved_keys != committed_keys
    ):
        raise ValueError(
            "resolved results must equal the complete ordered committed reference list"
        )
    return {
        key: item["artifact"] for key, item in zip(resolved_keys, resolved)
    }


def well_formed_attestation_ref(value):
    if (
        not isinstance(value, dict)
        or not {"anchor", "contentHash"} <= set(value)
        or set(value) - {"anchor", "contentHash", "signer"}
    ):
        return False
    # The signed result commits this reference. Its optional signer names the
    # source issuer/validator set, not necessarily the VerifyResult signer.
    if "signer" in value:
        try:
            parse_claim_reference(value["signer"])
        except ValueError:
            return False
    anchor = value.get("anchor")
    return (
        isinstance(anchor, dict)
        and set(anchor) == {"kind", "locator"}
        and isinstance(anchor.get("kind"), str)
        and anchor.get("kind") in {"storage-program", "ipfs", "https"}
        and isinstance(anchor.get("locator"), str)
        and bool(anchor["locator"])
        and isinstance(value.get("contentHash"), str)
        and re.fullmatch(r"[0-9a-f]{64}", value["contentHash"]) is not None
    )


def result_authority(trusted_context, result):
    matches = [
        authority for authority in trusted_context["verifyResultAuthorities"]
        if authority["scheme"] == result.get("scheme")
        and authority["method"] == result.get("method")
        and authority["recipeVersion"] == result.get("recipeVersion")
    ]
    return matches[0] if len(matches) == 1 else None


def authenticate_result(result, reference, trusted_context, generated_at):
    if not isinstance(result, dict):
        return False
    authority = result_authority(trusted_context, result)
    try:
        parsed = parse_claim_reference(
            f"{result.get('scheme')}:{result.get('identifier')}",
            registered_schemes=KNOWN_SCHEMES,
        )
        signed_hash = signed_component_hash(result)
    except (TypeError, ValueError, UnicodeError):
        return False
    valid_until = result.get("validUntil")
    if (
        authority is None
        or result.get("resultVersion") != "1"
        or not isinstance(result.get("reason"), str)
        or parsed.identity != (result.get("scheme"), result.get("identifier"))
        or not isinstance(result.get("decision"), str)
        or result.get("decision")
        not in {"pass", "fail", "error", "indeterminate"}
        or result.get("recipeVersion") != reference.get("recipeVersion")
        or signed_hash != reference.get("contentHash")
        or not verify_component(
            result, VERIFY_RESULT_DOMAIN, authority["signer"]
        )
        or not well_formed_attestation_ref(
            result.get("attestation")
        )
        or not finite_safe_number(result.get("fetchedAt"))
        or not finite_safe_number(result.get("verifiedAt"))
        or (
            "validUntil" in result
            and not finite_safe_number(valid_until)
        )
        or result["fetchedAt"] > result["verifiedAt"]
        or result["verifiedAt"] > generated_at
        or (valid_until is not None and result["verifiedAt"] > valid_until)
        or ("data" in result and not isinstance(result.get("data"), dict))
    ):
        return False
    return True


def expected_recipe_version(requirement, method, trusted_context):
    if not isinstance(method, str) or not method:
        return None
    versions = sorted(
        authority["recipeVersion"]
        for authority in trusted_context["verifyResultAuthorities"]
        if authority["scheme"] == requirement.get("scheme")
        and authority["method"] == method
    )
    if not versions:
        return None
    if "recipeVersion" in requirement:
        expected = requirement["recipeVersion"]
        return expected if expected in versions else None
    return versions[-1]


def qualification_preflight(
    claims, requirement, resolved_by_ref, trusted_context, decision_time
):
    if requirement.get("verificationRequired") is False:
        return True
    parameters = requirement.get("parameters") or {}
    selected_method = parameters.get("verificationMethod")
    if selected_method is not None:
        return expected_recipe_version(
            requirement, selected_method, trusted_context
        ) is not None
    methods = set()
    for claim, _ in matching_claims(
        claims, requirement, decision_time, presence_predicate=False
    ):
        reference = claim.get("verifiedBy")
        if not well_formed_result_ref(reference):
            continue
        result = resolved_by_ref.get(canonical_bytes(reference))
        if isinstance(result, dict) and result.get("scheme") == requirement.get("scheme"):
            methods.add(result.get("method"))
    return all(
        expected_recipe_version(requirement, method, trusted_context) is not None
        for method in methods
    )


def result_expiry(result, trusted_context):
    if "validUntil" in result:
        return result["validUntil"]
    authority = result_authority(trusted_context, result)
    if authority is None:
        return None
    return result["verifiedAt"] + authority["defaultMaxAgeSec"] * 1_000


def classify_presence(claims, requirement, decision_time, exact_ref=None):
    if "maxAge" in requirement or "recipeVersion" in requirement:
        return "error"
    matches = matching_claims(
        claims, requirement, decision_time,
        presence_predicate=True, exact_ref=exact_ref,
    )
    return "pass" if matches else "fail"


def classify_verified(
    claims, requirement, decision_time, committed_keys, resolved_by_ref,
    trusted_context, exact_ref=None, *, current_reuse=False,
):
    matches = matching_claims(
        claims, requirement, decision_time,
        presence_predicate=False, exact_ref=exact_ref,
    )
    outcomes = []
    for claim, parsed in matches:
        reference = claim.get("verifiedBy")
        if not well_formed_result_ref(reference):
            continue
        reference_key = canonical_bytes(reference)
        if reference_key not in committed_keys:
            continue
        result = resolved_by_ref[reference_key]
        if result is None:
            outcomes.append("indeterminate")
            continue
        if (
            result.get("scheme") != parsed.scheme
            or result.get("identifier") != parsed.identifier
        ):
            outcomes.append("fail")
            continue
        parameters = requirement.get("parameters") or {}
        selected_method = parameters.get(
            "verificationMethod", result.get("method")
        )
        expected_version = expected_recipe_version(
            requirement, selected_method, trusted_context
        )
        if expected_version is None:
            outcomes.append("error")
            continue
        if (
            result.get("method") != selected_method
            or result.get("recipeVersion") != expected_version
        ):
            continue
        expiry = result_expiry(result, trusted_context)
        if expiry is None:
            outcomes.append("error")
            continue
        claim_expiry = claim.get("expiresAt")
        if claim_expiry is not None:
            expiry = min(expiry, claim_expiry)
        max_age = requirement.get("maxAge")
        if decision_time > expiry or (
            max_age is not None
            and decision_time > result["verifiedAt"] + max_age * 1_000
        ):
            continue
        decision = result["decision"]
        if current_reuse and decision == "pass" and not currently_reusable(
            result, requirement, trusted_context, decision_time
        ):
            continue
        if decision == "pass" and not verified_parameters_match(
            result, requirement
        ):
            outcomes.append("fail")
        else:
            outcomes.append(decision)
    for outcome in ("pass", "fail", "error", "indeterminate"):
        if outcome in outcomes:
            return outcome
    return "fail"


def currently_reusable(result, requirement, trusted_context, trusted_now):
    """Apply VP-C1..VP-C3 at trusted current time, separately from replay."""

    if not exact_safe_integer(trusted_now, minimum=0) or result.get("decision") != "pass":
        return False
    parameters = requirement.get("parameters") or {}
    selected_method = parameters.get("verificationMethod", result.get("method"))
    expected_version = expected_recipe_version(
        requirement, selected_method, trusted_context
    )
    expiry = result_expiry(result, trusted_context)
    max_age = requirement.get("maxAge")
    return (
        expected_version is not None
        and result.get("method") == selected_method
        and result.get("recipeVersion") == expected_version
        and result["verifiedAt"] <= trusted_now
        and expiry is not None
        and trusted_now <= expiry
        and (
            max_age is None
            or trusted_now <= result["verifiedAt"] + max_age * 1_000
        )
        and verified_parameters_match(result, requirement)
    )


def classify_member(
    claims, member, decision_time, committed_keys, resolved_by_ref,
    trusted_context, exact_ref=None, *, current_reuse=False,
):
    if member.get("verificationRequired") is False:
        return classify_presence(claims, member, decision_time, exact_ref)
    if member.get("verificationRequired") is True:
        return classify_verified(
            claims, member, decision_time, committed_keys, resolved_by_ref,
            trusted_context, exact_ref, current_reuse=current_reuse,
        )
    return "error"


def selector_authorization_facts(
    vector, claims, decision_time, committed_keys, resolved_by_ref,
    trusted_context, *, current_reuse=False,
):
    requirement = vector["requirement"]
    selector = requirement.get("primaryClaimSelector")
    if selector is None:
        return {
            "selector_present": False,
            "controlled": True,
            "verified_selector": False,
            "presence_selector": False,
        }
    bundle = vector["bundle"]
    try:
        presented = parse_claim_reference(
            bundle.get("presentedBy"), registered_schemes=KNOWN_SCHEMES
        )
    except ValueError:
        return {
            "selector_present": True,
            "controlled": False,
            "verified_selector": False,
            "presence_selector": False,
        }
    resolved = exact_presented_claim(bundle, claims)
    controlled = exact_presenter_key_controlled(vector, claims)
    if presented.scheme != selector or resolved is None or not controlled:
        return {
            "selector_present": True,
            "controlled": False,
            "verified_selector": False,
            "presence_selector": False,
        }
    verified_selector = classify_verified(
        claims,
        {"scheme": selector, "verificationRequired": True},
        decision_time,
        committed_keys,
        resolved_by_ref,
        trusted_context,
        exact_ref=presented.canonical,
        current_reuse=current_reuse,
    ) == "pass"
    presence_members = [
        member for member in all_members(requirement)
        if member.get("scheme") == selector
        and member.get("verificationRequired") is False
        and classify_presence(
            claims, member, decision_time, presented.canonical
        ) == "pass"
    ]
    presence_selector = bool(presence_members)
    if any(
        member.get("scheme") == selector
        and member.get("verificationRequired") is True
        for member in requirement.get("required", [])
    ):
        presence_selector = False
    for group in requirement.get("oneOf", []):
        if not any(
            member.get("scheme") == selector
            and member.get("verificationRequired") is True
            for member in group
        ):
            continue
        exact_presence = any(
            member.get("scheme") == selector
            and member.get("verificationRequired") is False
            and classify_presence(
                claims, member, decision_time, presented.canonical
            ) == "pass"
            for member in group
        )
        other_pass = any(
            member.get("scheme") != selector
            and classify_member(
                claims, member, decision_time, committed_keys,
                resolved_by_ref, trusted_context,
            ) == "pass"
            for member in group
        )
        if not (exact_presence or other_pass):
            presence_selector = False
    return {
        "selector_present": True,
        "controlled": controlled,
        "verified_selector": verified_selector,
        "presence_selector": presence_selector,
    }


def selected_claim_is_authorized(
    vector, claims, decision_time, committed_keys, resolved_by_ref,
    trusted_context, *, current_reuse=False,
):
    facts = selector_authorization_facts(
        vector, claims, decision_time, committed_keys, resolved_by_ref,
        trusted_context, current_reuse=current_reuse,
    )
    return (
        not facts["selector_present"]
        or (
            facts["controlled"]
            and (facts["verified_selector"] or facts["presence_selector"])
        )
    )


def current_selected_claim_is_authorized(
    vector, claims, trusted_now, committed_keys, resolved_by_ref,
    trusted_context, historical_facts,
):
    if not historical_facts["selector_present"]:
        return True
    if not (
        historical_facts["controlled"]
        and (
            historical_facts["verified_selector"]
            or historical_facts["presence_selector"]
        )
        and exact_presenter_key_controlled(vector, claims)
    ):
        return False
    if historical_facts["presence_selector"]:
        return True
    return classify_verified(
        claims,
        {
            "scheme": vector["requirement"]["primaryClaimSelector"],
            "verificationRequired": True,
        },
        trusted_now,
        committed_keys,
        resolved_by_ref,
        trusted_context,
        exact_ref=vector["bundle"]["presentedBy"],
        current_reuse=True,
    ) == "pass"


def valid_requirement(requirement):
    if not isinstance(requirement, dict):
        return False
    try:
        canonical_bytes(requirement)
    except (TypeError, ValueError, UnicodeError):
        return False
    if requirement.get("requirementVersion") != "1":
        return False
    required = requirement.get("required")
    one_of = requirement.get("oneOf", [])
    if not isinstance(required, list) or not isinstance(one_of, list):
        return False
    if any(not isinstance(group, list) or not group for group in one_of):
        return False
    for member in all_members(requirement):
        if (
            not isinstance(member, dict)
            or type(member.get("verificationRequired")) is not bool
            or not isinstance(member.get("scheme"), str)
            or member.get("scheme") not in KNOWN_SCHEMES
            or (
                "parameters" in member
                and (
                    not isinstance(member.get("parameters"), dict)
                    or (
                        "verificationMethod" in member["parameters"]
                        and (
                            not isinstance(
                                member["parameters"]["verificationMethod"], str
                            )
                            or not member["parameters"]["verificationMethod"]
                        )
                    )
                )
            )
            or (
                "recipeVersion" in member
                and not exact_safe_integer(
                    member.get("recipeVersion"), minimum=1
                )
            )
            or (
                "maxAge" in member
                and not finite_safe_number(member.get("maxAge"), minimum=0)
            )
            or (
                member.get("verificationRequired") is False
                and ("maxAge" in member or "recipeVersion" in member)
            )
        ):
            return False
    selector = requirement.get("primaryClaimSelector")
    return selector is None or (isinstance(selector, str) and selector in KNOWN_SCHEMES)


def _reconstruct_admitted(vector, trusted_context, admission):
    """Historical decision reconstruction; not a protocol replay admission API."""
    record = vector.get("compositeRecord")
    requirement = vector.get("requirement")
    if not valid_composite_shape(record) or not valid_requirement(requirement):
        return "error"
    generated_at = record.get("generatedAt")
    if (
        admission.expected_verifier != trusted_context["compositeSigner"]
        or not verify_component(
            record, COMPOSITE_DOMAIN, admission.expected_verifier
        )
        or record.get("jobId") != admission.job_id
        or record.get("evaluatedParty") != admission.evaluated_party
        or not exact_safe_integer(generated_at, minimum=0)
        or generated_at > admission.trusted_now
    ):
        return "error"
    try:
        if (
            hash_hex(requirement) != admission.requirement_hash
            or admission.requirement_hash != record.get("requirementHash")
        ):
            return "error"
    except (TypeError, ValueError, UnicodeError):
        return "error"
    if not admission.registry_available or not admission.registry_authenticated:
        return "error"
    if not admission.bundle_available:
        return "indeterminate"
    bundle = vector.get("bundle")
    try:
        if hash_hex(bundle) != admission.bundle_input_hash:
            return "error"
    except (TypeError, ValueError, UnicodeError):
        return "error"
    if not verify_bundle(bundle, admission):
        return "error"
    if bundle.get("presentedBy") != admission.evaluated_party:
        return "error"
    try:
        unsigned_bundle = {
            key: value for key, value in bundle.items() if key != "presentation"
        }
        if hash_hex(unsigned_bundle) != record.get("bundleHash"):
            return "error"
        claims = canonical_claims(bundle)
        resolved_by_ref = bind_resolved_results(vector, record)
        committed = record_refs(record)
        committed_keys = {canonical_bytes(reference) for reference in committed}
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError):
        return "error"
    for claim, _ in claims:
        if "verifiedBy" in claim and not well_formed_result_ref(claim["verifiedBy"]):
            return "error"
    members = list(all_members(requirement))
    verified_schemes = {
        member["scheme"] for member in members
        if member["verificationRequired"] is True
    }
    for reference in committed:
        reference_key = canonical_bytes(reference)
        if not any(
            claim.get("verifiedBy") is not None
            and well_formed_result_ref(claim.get("verifiedBy"))
            and canonical_bytes(claim["verifiedBy"]) == reference_key
            and parsed.scheme in verified_schemes
            for claim, parsed in claims
        ):
            return "error"
        result = resolved_by_ref[reference_key]
        if result is not None and not authenticate_result(
            result, reference, trusted_context, generated_at
        ):
            return "error"
    if any(
        not qualification_preflight(
            claims, member, resolved_by_ref, trusted_context, generated_at
        )
        for member in members
    ):
        return "error"

    decision = aggregate_requirement(
        vector, claims, generated_at, committed_keys, resolved_by_ref, trusted_context,
    )
    return decision if decision == record.get("overallDecision") else "error"


def aggregate_requirement(
    vector, claims, decision_time, committed_keys, resolved_by_ref,
    trusted_context, *, current_reuse=False, historical_selector_facts=None,
):
    requirement = vector["requirement"]
    failures = []
    errors = []
    indeterminates = []
    for member in requirement.get("required", []):
        outcome = classify_member(
            claims, member, decision_time, committed_keys, resolved_by_ref,
            trusted_context, current_reuse=current_reuse,
        )
        if outcome == "fail":
            failures.append(outcome)
        elif outcome == "error":
            errors.append(outcome)
        elif outcome == "indeterminate":
            indeterminates.append(outcome)
    for group in requirement.get("oneOf", []):
        outcomes = [
            classify_member(
                claims, member, decision_time, committed_keys, resolved_by_ref,
                trusted_context, current_reuse=current_reuse,
            )
            for member in group
        ]
        if "pass" in outcomes:
            continue
        if "error" in outcomes:
            errors.append("oneOf")
        elif "indeterminate" in outcomes:
            indeterminates.append("oneOf")
        else:
            failures.append("oneOf")
    if not exact_presenter_key_controlled(vector, claims):
        failures.append("presenter")
    if requirement.get("primaryClaimSelector") is not None:
        if historical_selector_facts is None:
            selector_authorized = selected_claim_is_authorized(
                vector, claims, decision_time, committed_keys, resolved_by_ref,
                trusted_context, current_reuse=current_reuse,
            )
        else:
            selector_authorized = current_selected_claim_is_authorized(
                vector, claims, decision_time, committed_keys, resolved_by_ref,
                trusted_context, historical_selector_facts,
            )
        if not selector_authorized:
            failures.append("selector")
    if failures:
        decision = "fail"
    elif errors:
        decision = "error"
    elif indeterminates:
        decision = "indeterminate"
    else:
        decision = "pass"
    return decision


def admit_fixture_input(vector, trusted_context, runtime):
    if (
        not isinstance(runtime, PresenceEvaluationRuntime)
        or runtime.trusted_context is not trusted_context
    ):
        return None
    admission = runtime.admit(
        vector.get("authority") if isinstance(vector, dict) else None,
        vector.get("bundle") if isinstance(vector, dict) else None,
    )
    if admission is None:
        return None
    return admission


def evaluate(vector, trusted_context, runtime):
    """Active production acceptance uses retained phase inputs and current time."""
    admission = admit_fixture_input(vector, trusted_context, runtime)
    if admission is None:
        return "error"
    if not admission.bundle_available:
        return "error"
    decision = _reconstruct_admitted(vector, trusted_context, admission)
    if decision != "pass":
        return decision
    # Historical reconstruction is diagnostic. A record signed before the
    # verifier issued this consumed challenge cannot authorize current use.
    if vector["compositeRecord"]["generatedAt"] < admission.challenge_issued_at:
        return "error"
    # All artifacts have passed signature/reference/phase-input checks above.
    # A historical pass alone cannot authorize current reuse or progression.
    claims = canonical_claims(vector["bundle"])
    resolved = bind_resolved_results(vector, vector["compositeRecord"])
    refs = {canonical_bytes(ref) for ref in record_refs(vector["compositeRecord"])}
    historical_selector_facts = selector_authorization_facts(
        vector,
        claims,
        vector["compositeRecord"]["generatedAt"],
        refs,
        resolved,
        trusted_context,
    )
    return aggregate_requirement(
        vector, claims, admission.trusted_now, refs, resolved, trusted_context,
        current_reuse=True,
        historical_selector_facts=historical_selector_facts,
    )


def reconstruct_fixture_once(vector, trusted_context, runtime=None):
    """Non-authorizing fixture diagnostic; no signed DACS-5 replay claim."""
    try:
        if runtime is None:
            runtime = PresenceEvaluationRuntime(trusted_context)
    except (TypeError, ValueError):
        return "error"
    if (
        not isinstance(runtime, PresenceEvaluationRuntime)
        or runtime.trusted_context is not trusted_context
    ):
        return "error"
    if isinstance(vector, dict) and vector.get("bundle") is None:
        authority = vector.get("authority")
        if (
            isinstance(authority, dict)
            and set(authority) == {"kind", "invocation", "nonce"}
            and authority.get("kind") == "vet-invocation"
            and isinstance(authority.get("invocation"), str)
        ):
            context = runtime._trusted_invocation(authority["invocation"])
            if context is not None and context["bundleAvailable"] is False:
                # Standalone CVR reliance can diagnose exact-bundle
                # unavailability, but cannot admit a new session attempt:
                # there are no presentation bytes from which to extract SN-4.
                diagnostic = UnavailableBundleDiagnostic(
                    context["expectedVerifier"], context["jobId"],
                    context["evaluatedParty"], context["trustedNow"],
                    context["requirementHash"], context["registryAvailable"],
                    context["registryAuthenticated"],
                )
                return _reconstruct_admitted(vector, trusted_context, diagnostic)
    admission = admit_fixture_input(vector, trusted_context, runtime)
    if admission is None:
        return "error"
    return _reconstruct_admitted(vector, trusted_context, admission)


class PresenceOnlyClaimVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_generator_is_deterministic(self):
        subprocess.run(
            ["python3", str(GENERATOR), "--check"], cwd=ROOT, check=True
        )

    def test_header_count_hash_and_names(self):
        vectors = self.document["vectors"]
        self.assertEqual(self.document["count"], len(vectors))
        self.assertEqual(
            self.document["hash"], hashlib.sha256(canonical_bytes(vectors)).hexdigest()
        )
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_fractional_max_age_is_a_valid_verified_duration(self):
        self.assertTrue(valid_requirement({
            "requirementVersion": "1",
            "required": [{
                "scheme": "key",
                "verificationRequired": True,
                "maxAge": 0.5,
            }],
        }))
        for value in (
            True, -0.5, float("nan"), float("inf"), 10**1000, -(10**1000)
        ):
            with self.subTest(value=repr(value)):
                self.assertFalse(valid_requirement({
                    "requirementVersion": "1",
                    "required": [{
                        "scheme": "key",
                        "verificationRequired": True,
                        "maxAge": value,
                    }],
                }))

    def test_sr1_root_uses_top_level_nonce_and_siwd_uses_message_nonce(self):
        issuance = copy.deepcopy(
            self.document["trustedContext"]["nonceIssuances"][0]
        )
        sr1 = {
            "sessionNonce": issuance["nonce"],
            "presentation": {
                "kind": "sr1-root",
                "rootClaim": issuance["evaluatedParty"],
                "aggregateSignature": "fixture",
            },
        }
        self.assertEqual(issuance["nonce"], presentation_nonce(sr1))
        ledger = NonceLedger([issuance])
        ledger.consume(
            issuance["challengeId"], presentation_nonce(sr1), issuance["issuedAt"]
        )
        with self.assertRaises(NonceRejected):
            ledger.consume(
                issuance["challengeId"], presentation_nonce(sr1),
                issuance["issuedAt"],
            )

        for mutation in ("missing", "wrong"):
            with self.subTest(sr1=mutation):
                candidate = copy.deepcopy(sr1)
                if mutation == "missing":
                    candidate.pop("sessionNonce")
                else:
                    candidate["sessionNonce"] = "00" * 16
                fresh = NonceLedger([issuance])
                with self.assertRaises(NonceRejected):
                    fresh.consume(
                        issuance["challengeId"], presentation_nonce(candidate),
                        issuance["issuedAt"],
                    )
                self.assertFalse(fresh.consumed(issuance["challengeId"]))

        siwd = {
            "sessionNonce": issuance["nonce"],
            "presentation": {
                "kind": "siwd",
                "message": "Nonce: " + "00" * 16,
            },
        }
        self.assertEqual("00" * 16, presentation_nonce(siwd))
        fresh = NonceLedger([issuance])
        with self.assertRaises(NonceRejected):
            fresh.consume(
                issuance["challengeId"], presentation_nonce(siwd),
                issuance["issuedAt"],
            )
        self.assertFalse(fresh.consumed(issuance["challengeId"]))

    def test_siwd_nonce_requires_exactly_one_message_nonce_field(self):
        # DACS-1 §6.3.2 reads the single EIP-4361 Nonce field of the exact
        # SIWD message.  An ambiguous message supplies no nonce, so it neither
        # authorizes the attempt nor consumes the issued challenge.
        issuance = copy.deepcopy(
            self.document["trustedContext"]["nonceIssuances"][0]
        )
        prefix = "example.test wants you to sign in with your account:\n"

        def siwd(message):
            return {"presentation": {"kind": "siwd", "message": message}}

        single = siwd(prefix + "Nonce: " + issuance["nonce"])
        self.assertEqual(issuance["nonce"], presentation_nonce(single))
        ledger = NonceLedger([issuance])
        ledger.consume(
            issuance["challengeId"], presentation_nonce(single), issuance["issuedAt"]
        )
        self.assertTrue(ledger.consumed(issuance["challengeId"]))

        for label, message in (
            ("issued then other", "Nonce: " + issuance["nonce"] + "\nNonce: " + "00" * 16),
            ("other then issued", "Nonce: " + "00" * 16 + "\nNonce: " + issuance["nonce"]),
            ("issued twice", "Nonce: " + issuance["nonce"] + "\nNonce: " + issuance["nonce"]),
            ("empty", "Nonce: "),
        ):
            with self.subTest(label=label):
                candidate = siwd(prefix + message)
                self.assertIsNone(presentation_nonce(candidate))
                fresh = NonceLedger([issuance])
                with self.assertRaises(NonceRejected):
                    fresh.consume(
                        issuance["challengeId"], presentation_nonce(candidate),
                        issuance["issuedAt"],
                    )
                self.assertFalse(fresh.consumed(issuance["challengeId"]))

    def test_all_vectors_execute(self):
        runtime = PresenceEvaluationRuntime(self.document["trustedContext"])
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    vector["expected"],
                    reconstruct_fixture_once(vector, self.document["trustedContext"], runtime),
                )

    def test_all_non_signature_negative_artifacts_are_genuinely_signed(self):
        for vector in self.document["vectors"]:
            name = vector["name"]
            if vector["bundle"] is not None:
                self.assertEqual(
                    name not in {
                        "invalid-bundle-presentation-rejected",
                        "authentic-bundle-signature-without-claim-membership",
                    },
                    verify_bundle(vector["bundle"]),
                    name,
                )
            self.assertEqual(
                name not in {
                    "invalid-composite-signature-rejected",
                    "invalid-composite-still-rejects-without-bundle",
                },
                verify_component(
                    vector["compositeRecord"],
                    COMPOSITE_DOMAIN,
                    self.document["trustedContext"]["compositeSigner"],
                ),
                name,
            )
            for resolved in vector["resolvedResults"]:
                if resolved["artifact"] is None:
                    continue
                expected_signer = expected_result_signer(
                    self.document["trustedContext"], resolved["artifact"]
                )
                self.assertEqual(
                    name != "authorized-result-signer-substitution-rejected",
                    expected_signer is not None
                    and verify_component(
                        resolved["artifact"], VERIFY_RESULT_DOMAIN, expected_signer
                    ),
                    name,
                )

    def test_identity_bundle_accepts_signed_additive_top_level_members(self):
        private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("24" * 32))
        claim = "key:" + private.public_key().public_bytes_raw().hex()
        def signed(presented_at):
            unsigned = {
                "bundleVersion": "1",
                "presentedBy": claim,
                "presentedAt": presented_at,
                "claims": [{"ref": claim}],
                "futureMinorContext": {"advisory": ["retained", "inert"]},
            }
            payload = (BUNDLE_DOMAIN + hash_hex(unsigned)).encode("ascii")
            signature = base64.urlsafe_b64encode(private.sign(payload)).rstrip(b"=")
            return {
                **unsigned,
                "presentation": {
                    "kind": "per-claim",
                    "signatures": [
                        {"ref": claim, "signature": signature.decode("ascii")}
                    ],
                },
            }

        for value in (0, 0.5, -0.5):
            with self.subTest(valid_presented_at=value):
                self.assertTrue(verify_bundle(signed(value)))
        for value in (True, "0"):
            with self.subTest(invalid_presented_at=value):
                self.assertFalse(verify_bundle(signed(value)))
        unsigned_mutation = signed(0)
        unsigned_mutation["presentedAt"] = 0.5
        self.assertFalse(verify_bundle(unsigned_mutation))

    def test_authentic_outsider_signature_is_a_structural_error(self):
        by_name = {vector["name"]: vector for vector in self.document["vectors"]}
        control = by_name["required-presence-key-with-issued-at"]
        vector = by_name["authentic-bundle-signature-without-claim-membership"]
        context = self.document["trustedContext"]
        self.assertTrue(verify_bundle(control["bundle"]))
        self.assertEqual("pass", reconstruct_fixture_once(control, context))
        self.assertEqual(
            "pass", evaluate(control, context, PresenceEvaluationRuntime(context))
        )

        # The negative has an authentic included-presenter signature AND an
        # authentic outsider signature over the same complete signed bytes.
        # Nothing about signature validity or presenter control masks BR-2.
        bundle = vector["bundle"]
        unsigned = {key: value for key, value in bundle.items() if key != "presentation"}
        payload = (BUNDLE_DOMAIN + hash_hex(unsigned)).encode("ascii")
        claims = canonical_claims(bundle)
        identities = {parsed.identity for _, parsed in claims}
        self.assertEqual(2, len(bundle["presentation"]["signatures"]))
        signer_identities = []
        for signature in bundle["presentation"]["signatures"]:
            signer = parse_claim_reference(
                signature["ref"], registered_schemes=KNOWN_SCHEMES
            )
            self.assertEqual("key", signer.scheme)
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer.identifier)).verify(
                b64url_decode(signature["signature"]), payload
            )
            signer_identities.append(signer.identity)
        self.assertIn(signer_identities[0], identities)
        self.assertNotIn(signer_identities[1], identities)
        self.assertTrue(exact_presenter_key_controlled(vector, claims))
        self.assertEqual("pass", vector["compositeRecord"]["overallDecision"])
        self.assertFalse(verify_bundle(bundle))
        self.assertEqual("error", reconstruct_fixture_once(vector, context))
        self.assertEqual(
            "error", evaluate(vector, context, PresenceEvaluationRuntime(context))
        )

    def test_every_result_reference_uses_the_core_b2_signed_scope(self):
        resolved = [
            item
            for vector in self.document["vectors"]
            for item in vector["resolvedResults"]
            if item["artifact"] is not None
        ]
        self.assertTrue(resolved)
        for item in resolved:
            with self.subTest(locator=item["ref"]["anchor"]["locator"]):
                self.assertEqual(
                    signed_component_hash(item["artifact"]),
                    item["ref"]["contentHash"],
                )

    def test_signature_mutation_preserves_reference_hash_but_fails_authentication(self):
        item = next(
            item
            for vector in self.document["vectors"]
            for item in vector["resolvedResults"]
            if item["artifact"] is not None
        )
        original = item["artifact"]
        mutated = json.loads(json.dumps(original))
        signature = mutated["signature"]["value"]
        mutated["signature"]["value"] = (
            ("A" if signature[0] != "A" else "B") + signature[1:]
        )
        self.assertEqual(signed_component_hash(original), signed_component_hash(mutated))
        self.assertEqual(item["ref"]["contentHash"], signed_component_hash(mutated))
        expected_signer = expected_result_signer(
            self.document["trustedContext"], mutated
        )
        self.assertFalse(
            verify_component(mutated, VERIFY_RESULT_DOMAIN, expected_signer)
        )

    def test_valid_alternate_signature_cannot_replace_the_trusted_authority(self):
        vector = next(
            vector for vector in self.document["vectors"]
            if vector["name"] == "authorized-result-signer-substitution-rejected"
        )
        resolved = vector["resolvedResults"][0]
        self.assertEqual(
            resolved["ref"]["contentHash"],
            signed_component_hash(resolved["artifact"]),
        )
        signature = resolved["artifact"]["signature"]
        self.assertNotEqual(
            signature["signer"],
            self.document["trustedContext"]["verifyResultAuthorities"][1]["signer"],
        )
        self.assertEqual(
            "error", reconstruct_fixture_once(vector, self.document["trustedContext"])
        )

    def test_presence_only_members_have_no_result_refs_in_passing_records(self):
        for vector in self.document["vectors"]:
            members = list(all_members(vector["requirement"]))
            if vector["expected"] != "pass" or not members:
                continue
            if all(member["verificationRequired"] is False for member in members):
                with self.subTest(vector=vector["name"]):
                    self.assertEqual([], record_refs(vector["compositeRecord"]))

    def test_control_boundary_vectors_are_distinguishing(self):
        expected = {
            "presence-key-selector-has-independent-control": "pass",
            "presence-lei-selector-does-not-establish-control": "fail",
            "different-verified-same-scheme-cannot-launder-selector": "fail",
            "unauthorized-selector-dominates-unavailable-member": "fail",
        }
        by_name = {vector["name"]: vector for vector in self.document["vectors"]}
        for name, verdict in expected.items():
            self.assertEqual(
                verdict,
                reconstruct_fixture_once(
                    by_name[name], self.document["trustedContext"]
                ),
            )

    def test_presenter_control_vectors_are_distinguishing(self):
        by_name = {vector["name"]: vector for vector in self.document["vectors"]}
        expected = {
            "required-presence-key-with-issued-at": "pass",
            "no-selector-unrelated-cosigner-is-uncontrolled": "fail",
            "no-selector-uncontrolled-signed-pass-mismatch-is-error": "error",
            "selector-unrelated-cosigner-is-uncontrolled": "fail",
            "no-selector-absent-presenter-is-semantic-fail": "fail",
            "selector-absent-presenter-is-semantic-fail": "fail",
            "no-selector-parameterized-cf3-presenter-controls": "pass",
            "selector-parameterized-cf3-presenter-controls": "pass",
            "optional-failing-verification-does-not-defeat-presence": "pass",
            "optional-stale-verification-does-not-defeat-presence": "pass",
            "stale-optional-key-result-does-not-remove-key-control": "pass",
        }
        for name, verdict in expected.items():
            with self.subTest(vector=name):
                vector = by_name[name]
                self.assertTrue(verify_bundle(vector["bundle"]))
                runtime = PresenceEvaluationRuntime(self.document["trustedContext"])
                self.assertEqual(
                    verdict,
                    evaluate(vector, self.document["trustedContext"], runtime),
                )
                challenge_id = self.document["trustedContext"]["vetInvocations"][
                    vector["authority"]["invocation"]
                ]["challengeId"]
                self.assertTrue(runtime.nonce_ledger.consumed(challenge_id))

    def test_presented_claim_uniqueness_is_order_independent(self):
        by_name = {vector["name"]: vector for vector in self.document["vectors"]}
        for name in (
            "no-selector-absent-presenter-is-semantic-fail",
            "selector-absent-presenter-is-semantic-fail",
        ):
            with self.subTest(vector=name):
                vector = by_name[name]
                self.assertTrue(verify_bundle(vector["bundle"]))
                claims = canonical_claims(vector["bundle"])
                self.assertIsNone(exact_presented_claim(vector["bundle"], claims))
                self.assertEqual(
                    "fail",
                    reconstruct_fixture_once(
                        vector, self.document["trustedContext"]
                    ),
                )

        repeated = by_name["byte-identical-presenter-claim-repetition-collapses"]
        repeated_claims = canonical_claims(repeated["bundle"])
        self.assertIsNotNone(exact_presented_claim(repeated["bundle"], repeated_claims))
        self.assertEqual(
            "pass",
            reconstruct_fixture_once(repeated, self.document["trustedContext"]),
        )

        for name in (
            "distinct-same-identity-presenter-claims-are-ambiguous",
            "distinct-same-identity-presenter-claims-reversed-are-ambiguous",
        ):
            with self.subTest(vector=name):
                vector = by_name[name]
                self.assertTrue(verify_bundle(vector["bundle"]))
                claims = canonical_claims(vector["bundle"])
                self.assertIsNone(exact_presented_claim(vector["bundle"], claims))
                self.assertEqual(
                    "fail",
                    reconstruct_fixture_once(
                        vector, self.document["trustedContext"]
                    ),
                )
                self.assertEqual(
                    "fail",
                    evaluate(
                        vector,
                        self.document["trustedContext"],
                        PresenceEvaluationRuntime(self.document["trustedContext"]),
                    ),
                )

    def test_selector_current_time_preserves_only_the_historical_presence_arm(self):
        by_name = {vector["name"]: vector for vector in self.document["vectors"]}
        verified = by_name[
            "selector-verified-status-expires-after-historical-decision"
        ]
        presence = by_name[
            "historical-selector-presence-arm-is-not-rerun-at-trusted-now"
        ]
        context = self.document["trustedContext"]
        claims = canonical_claims(verified["bundle"])
        refs = {canonical_bytes(ref) for ref in record_refs(verified["compositeRecord"])}
        resolved = bind_resolved_results(verified, verified["compositeRecord"])
        historical = selector_authorization_facts(
            verified, claims, verified["compositeRecord"]["generatedAt"],
            refs, resolved, context,
        )
        self.assertTrue(historical["controlled"])
        self.assertTrue(historical["verified_selector"])
        self.assertFalse(historical["presence_selector"])
        self.assertEqual([], verified["requirement"]["required"])
        group = verified["requirement"]["oneOf"][0]
        self.assertEqual(
            ["fail", "pass"],
            [classify_member(
                claims, member, verified["evaluatedAt"], refs, resolved,
                context, current_reuse=True,
            ) for member in group],
        )
        self.assertTrue(exact_presenter_key_controlled(verified, claims))

        # Inclusive expiry is an accepting control, followed by the first
        # invalid millisecond. The DID arm still satisfies the members at
        # both times; only exact verified-selector requalification changes.
        expiry = verified["resolvedResults"][0]["artifact"]["validUntil"]
        for trusted_now, expected in ((expiry, "pass"), (expiry + 1, "fail")):
            with self.subTest(trusted_now=trusted_now):
                boundary = copy.deepcopy(context)
                boundary["vetInvocations"][verified["authority"]["invocation"]][
                    "trustedNow"
                ] = trusted_now
                self.assertEqual("pass", reconstruct_fixture_once(verified, boundary))
                self.assertEqual(
                    expected,
                    evaluate(verified, boundary, PresenceEvaluationRuntime(boundary)),
                )
        for vector in (verified, presence):
            self.assertEqual(
                "pass",
                reconstruct_fixture_once(vector, self.document["trustedContext"]),
            )
        self.assertEqual(
            "fail",
            evaluate(
                verified,
                self.document["trustedContext"],
                PresenceEvaluationRuntime(self.document["trustedContext"]),
            ),
        )
        self.assertEqual(
            "pass",
            evaluate(
                presence,
                self.document["trustedContext"],
                PresenceEvaluationRuntime(self.document["trustedContext"]),
            ),
        )

    def test_requirement_shape_vectors_are_distinguishing(self):
        by_name = {vector["name"]: vector for vector in self.document["vectors"]}
        invalid = {
            "presence-max-age-is-invalid",
            "presence-recipe-version-is-invalid",
            "verification-required-must-be-boolean",
            "empty-oneof-group-is-invalid",
            "oneof-passing-member-cannot-mask-unknown-scheme",
            "presence-parameters-must-be-an-object",
        }
        for name in invalid:
            with self.subTest(vector=name):
                vector = by_name[name]
                self.assertEqual("error", vector["expected"])
                fallback = (
                    "fail"
                    if name in {
                        "empty-oneof-group-is-invalid",
                        "presence-parameters-must-be-an-object",
                    }
                    else "pass"
                )
                self.assertEqual(
                    fallback, vector["compositeRecord"]["overallDecision"]
                )
                self.assertEqual(
                    "error",
                    reconstruct_fixture_once(
                        vector, self.document["trustedContext"]
                    ),
                )
        self.assertEqual(
            "pass", reconstruct_fixture_once(
                by_name["empty-member-collections-are-vacuously-satisfied"],
                self.document["trustedContext"],
            )
        )

    def test_registry_authentication_precedes_bundle_availability(self):
        by_name = {vector["name"]: vector for vector in self.document["vectors"]}
        self.assertEqual(
            "indeterminate", reconstruct_fixture_once(
                by_name["exact-bundle-unavailable-is-indeterminate"],
                self.document["trustedContext"],
            )
        )
        self.assertEqual(
            "error", reconstruct_fixture_once(
                by_name["invalid-registry-precedes-unavailable-bundle"],
                self.document["trustedContext"],
            )
        )

    def test_missing_bundle_diagnostic_never_admits_active_use(self):
        by_name = {vector["name"]: vector for vector in self.document["vectors"]}
        unavailable = by_name["exact-bundle-unavailable-is-indeterminate"]
        context = self.document["trustedContext"]
        challenge = context["vetInvocations"][unavailable["authority"]["invocation"]]["challengeId"]
        runtime = PresenceEvaluationRuntime(context)
        self.assertEqual("indeterminate", reconstruct_fixture_once(unavailable, context, runtime))
        self.assertFalse(runtime.nonce_ledger.consumed(challenge))
        self.assertEqual("error", evaluate(unavailable, context, runtime))
        self.assertFalse(runtime.nonce_ledger.consumed(challenge))

        # Signed record, exact requirement and authenticated registry precede
        # the non-authorizing unavailable-bundle disposition.
        self.assertEqual("error", reconstruct_fixture_once(
            by_name["invalid-composite-still-rejects-without-bundle"], context
        ))
        self.assertEqual("error", reconstruct_fixture_once(
            by_name["invalid-registry-precedes-unavailable-bundle"], context
        ))
        wrong_requirement = copy.deepcopy(unavailable)
        wrong_requirement["requirement"] = {
            "requirementVersion": "1", "required": []
        }
        self.assertEqual("error", reconstruct_fixture_once(wrong_requirement, context))
        mismatched_context = copy.deepcopy(context)
        self.assertEqual("error", reconstruct_fixture_once(
            unavailable, context, PresenceEvaluationRuntime(mismatched_context)
        ))
        available_context = copy.deepcopy(context)
        available_context["vetInvocations"][unavailable["authority"]["invocation"]][
            "bundleAvailable"
        ] = True
        self.assertEqual("error", reconstruct_fixture_once(unavailable, available_context))

    def test_verified_predicates_use_authenticated_result_data(self):
        by_name = {vector["name"]: vector for vector in self.document["vectors"]}
        for name, expected in {
            "verified-parameters-use-authenticated-result-data": "pass",
            "verified-parameters-ignore-matching-bundle-metadata": "fail",
            "one-authenticated-result-may-satisfy-multiple-predicates": "pass",
        }.items():
            with self.subTest(vector=name):
                self.assertEqual(
                    expected,
                    reconstruct_fixture_once(
                        by_name[name], self.document["trustedContext"]
                    ),
                )

    def test_complete_ordered_result_projection_is_required(self):
        vector = next(
            value for value in self.document["vectors"]
            if value["name"]
            == "complete-ordered-freshness-then-deal-specific-results"
        )
        self.assertEqual(2, len(record_refs(vector["compositeRecord"])))
        self.assertEqual(2, len(vector["resolvedResults"]))
        for resolved in (
            [],
            list(reversed(vector["resolvedResults"])),
            [*vector["resolvedResults"], vector["resolvedResults"][0]],
        ):
            changed = json.loads(json.dumps(vector))
            changed["resolvedResults"] = resolved
            with self.subTest(count=len(resolved)):
                self.assertEqual(
                    "error",
                    reconstruct_fixture_once(changed, self.document["trustedContext"]),
                )

    def test_historical_replay_and_current_reuse_have_distinct_clocks(self):
        by_name = {vector["name"]: vector for vector in self.document["vectors"]}
        historical = by_name[
            "signed-generated-at-reconstructs-historical-decision"
        ]
        changed = json.loads(json.dumps(historical))
        changed["evaluatedAt"] = SAFE_INTEGER
        self.assertEqual(
            "pass",
            reconstruct_fixture_once(changed, self.document["trustedContext"]),
        )
        result = historical["resolvedResults"][0]["artifact"]
        requirement = historical["requirement"]["required"][0]
        invocation = self.document["trustedContext"]["vetInvocations"][
            historical["authority"]["invocation"]
        ]
        self.assertLessEqual(
            result["validUntil"], invocation["trustedNow"]
        )
        self.assertFalse(
            currently_reusable(
                result, requirement, self.document["trustedContext"],
                invocation["trustedNow"],
            )
        )

    def test_cross_session_pass_reuse_keeps_results_session_agnostic(self):
        vectors = [
            vector for vector in self.document["vectors"]
            if vector["name"].startswith("cross-session-pass-reuse-")
        ]
        self.assertEqual(2, len(vectors))
        self.assertEqual(
            vectors[0]["resolvedResults"][0], vectors[1]["resolvedResults"][0]
        )
        self.assertNotEqual(
            vectors[0]["compositeRecord"]["jobId"],
            vectors[1]["compositeRecord"]["jobId"],
        )
        self.assertNotEqual(
            vectors[0]["authority"]["nonce"], vectors[1]["authority"]["nonce"]
        )
        artifact = vectors[0]["resolvedResults"][0]["artifact"]
        self.assertFalse(
            {"jobId", "evaluatedParty", "phaseIndex", "attempt", "sessionNonce"}
            & set(artifact)
        )
        for vector in vectors:
            invocation = self.document["trustedContext"]["vetInvocations"][
                vector["authority"]["invocation"]
            ]
            self.assertTrue(
                currently_reusable(
                    artifact,
                    vector["requirement"]["required"][0],
                    self.document["trustedContext"],
                    invocation["trustedNow"],
                )
            )

    def test_runtime_is_required_and_consumes_one_admitted_nonce(self):
        vector = self.document["vectors"][0]
        self.assertEqual(
            "error", evaluate(vector, self.document["trustedContext"], None)
        )
        runtime = PresenceEvaluationRuntime(self.document["trustedContext"])
        self.assertEqual(
            vector["expected"],
            evaluate(vector, self.document["trustedContext"], runtime),
        )
        challenge_id = self.document["trustedContext"]["vetInvocations"][
            vector["authority"]["invocation"]
        ]["challengeId"]
        self.assertTrue(runtime.nonce_ledger.consumed(challenge_id))
        context = self.document["trustedContext"]["vetInvocations"][
            vector["authority"]["invocation"]
        ]
        self.assertEqual(context["expectedVerifier"], context["phaseOrchestrator"])

    def test_claim_reference_did_percent_bytes_are_preserved(self):
        for value in (
            "did:example:subject%3Aretained",
            "did:example:subject%3aretained",
        ):
            self.assertEqual(value.split(":", 1)[1], parse_ref(value)[1])
        self.assertNotEqual(
            parse_ref("did:example:subject%3Aretained"),
            parse_ref("did:example:subject%3aretained"),
        )
        first = parse_claim_reference(
            "did:example:subject?context=one%3Atwo",
            registered_schemes=KNOWN_SCHEMES,
        )
        second = parse_claim_reference(
            "did:example:subject?context=three",
            registered_schemes=KNOWN_SCHEMES,
        )
        self.assertNotEqual(first.canonical, second.canonical)
        self.assertEqual(first.identity, second.identity)
        for value in (
            "did:example:subject%A",
            "did:example:subject%3g",
            "did:example:subject%AB%",
            "Did:example:subject",
            "did:example:subject?context=one%3atwo",
        ):
            with self.subTest(reference=value), self.assertRaises(ValueError):
                parse_ref(value)

    def test_valid_until_container_is_error_without_throwing(self):
        vector = next(
            value for value in self.document["vectors"]
            if value["name"] == "verify-result-valid-until-container-is-error"
        )
        self.assertEqual(
            "error", reconstruct_fixture_once(vector, self.document["trustedContext"])
        )

    def test_active_acceptance_requalifies_at_trusted_current_time(self):
        context = self.document["trustedContext"]
        by_name = {vector["name"]: vector for vector in self.document["vectors"]}
        historical = by_name["signed-generated-at-reconstructs-historical-decision"]
        self.assertEqual("pass", reconstruct_fixture_once(historical, context))
        self.assertEqual("fail", evaluate(historical, context, PresenceEvaluationRuntime(context)))
        for vector in self.document["vectors"]:
            if vector["name"].startswith("cross-session-pass-reuse-"):
                self.assertEqual("pass", evaluate(vector, context, PresenceEvaluationRuntime(context)))
            if vector["bundleAvailable"] is False:
                self.assertEqual("error", evaluate(vector, context, PresenceEvaluationRuntime(context)))

    def test_active_acceptance_requires_record_after_verifier_challenge_issue(self):
        vector = next(
            value for value in self.document["vectors"]
            if value["name"] == "historical-selector-presence-arm-is-not-rerun-at-trusted-now"
        )
        generated_at = vector["compositeRecord"]["generatedAt"]
        invocation = vector["authority"]["invocation"]
        challenge = self.document["trustedContext"]["vetInvocations"][invocation]["challengeId"]
        for issued_at, expected in ((generated_at, "pass"), (generated_at + 1, "error")):
            with self.subTest(challenge_issued_at=issued_at):
                context = copy.deepcopy(self.document["trustedContext"])
                issuance = next(
                    item for item in context["nonceIssuances"]
                    if item["challengeId"] == challenge
                )
                issuance["issuedAt"] = issued_at
                runtime = PresenceEvaluationRuntime(context)
                self.assertEqual("pass", reconstruct_fixture_once(vector, context))
                self.assertEqual(expected, evaluate(vector, context, runtime))
                self.assertTrue(runtime.nonce_ledger.consumed(challenge))

    def test_presentation_nonce_consumption_ignores_caller_projection(self):
        vector = next(
            value for value in self.document["vectors"]
            if value["name"] == "required-presence-key-with-issued-at"
        )
        context = self.document["trustedContext"]
        challenge = context["vetInvocations"][vector["authority"]["invocation"]]["challengeId"]
        self.assertTrue(verify_bundle(vector["bundle"]))
        self.assertEqual(vector["authority"]["nonce"], presentation_nonce(vector["bundle"]))
        projected = copy.deepcopy(vector)
        projected["authority"]["nonce"] = "00" * 16
        self.assertNotEqual(projected["authority"]["nonce"], presentation_nonce(projected["bundle"]))
        for entrypoint in (evaluate, reconstruct_fixture_once):
            with self.subTest(entrypoint=entrypoint.__name__):
                self.assertEqual(
                    "pass", entrypoint(vector, context, PresenceEvaluationRuntime(context))
                )
                runtime = PresenceEvaluationRuntime(context)
                self.assertEqual("error", entrypoint(projected, context, runtime))
                self.assertTrue(runtime.nonce_ledger.consumed(challenge))
                self.assertEqual("error", entrypoint(vector, context, runtime))

    def test_required_composite_collections_cannot_default_to_empty(self):
        record = self.document["vectors"][0]["compositeRecord"]
        self.assertTrue(valid_composite_shape(record))
        for field in ("recordVersion", "freshness", "dealSpecific", "supplementary"):
            changed = dict(record)
            del changed[field]
            with self.subTest(missing=field):
                self.assertFalse(valid_composite_shape(changed))
        self.assertTrue(valid_composite_shape({**record, "extension": {"opaque": True}}))

    def test_retained_phase_inputs_and_registry_pin_are_required(self):
        vector = self.document["vectors"][0]
        original = self.document["trustedContext"]
        invocation_id = vector["authority"]["invocation"]
        for field in ("requirementHash", "bundleInputHash", "sessionContext", "recipeRegistryVersion"):
            changed = json.loads(json.dumps(original))
            del changed["vetInvocations"][invocation_id][field]
            with self.subTest(missing=field):
                self.assertEqual("error", reconstruct_fixture_once(vector, changed))
        for field in ("requirementHash", "bundleInputHash"):
            changed = json.loads(json.dumps(original))
            changed["vetInvocations"][invocation_id][field] = "0" * 64
            with self.subTest(input=field):
                self.assertEqual("error", reconstruct_fixture_once(vector, changed))
        changed = json.loads(json.dumps(original))
        changed["recipeRegistryVersion"] += 1
        self.assertEqual("error", reconstruct_fixture_once(vector, changed))
        changed = json.loads(json.dumps(original))
        changed["authenticatedSessionStarts"] = {}
        self.assertEqual("error", reconstruct_fixture_once(vector, changed))
        self.assertEqual(vector["expected"], reconstruct_fixture_once(vector, original))

    def test_source_attestation_signer_is_optional_and_may_be_an_issuer(self):
        reference = {
            "anchor": {"kind": "https", "locator": "https://example.invalid/source"},
            "contentHash": "0" * 64,
        }
        self.assertTrue(well_formed_attestation_ref(reference))
        self.assertTrue(well_formed_attestation_ref({
            **reference, "signer": "did:example:issuer",
        }))
        self.assertFalse(well_formed_attestation_ref({
            **reference, "signer": None,
        }))

    def test_requirement_and_reference_enums_have_closed_scalar_shapes(self):
        for value in ([], {}, None, True):
            with self.subTest(value=value):
                self.assertFalse(valid_requirement({
                    "requirementVersion": "1", "required": [{
                        "scheme": value, "verificationRequired": False,
                    }],
                }))
                self.assertFalse(well_formed_result_ref({
                    "anchor": {"kind": value, "locator": "fixture"},
                    "contentHash": "0" * 64, "recipeVersion": 1,
                }))
        self.assertTrue(valid_requirement({
            "requirementVersion": "1", "required": [],
        }))

    def test_published_control_fixture_is_the_presence_only_key_case(self):
        fixture = json.loads(CONTROL_FIXTURE.read_text(encoding="utf-8"))
        vector = next(
            case for case in fixture["cases"]
            if case["name"] == "vet-control-key-presentation-accept"
        )
        value = vector["evaluations"]["result"]["input"]
        claim = value["bundle"]["claims"][0]
        member = value["requirement"]["required"][0]
        self.assertNotIn("verifiedBy", claim)
        self.assertIn("issuedAt", claim)
        self.assertFalse(member["verificationRequired"])
        self.assertEqual("pass", vector["expectedOutput"])

    def test_specs_define_all_presence_rules_and_versions(self):
        dacs1 = DACS1.read_text(encoding="utf-8")
        dacs2 = DACS2.read_text(encoding="utf-8")
        self.assertIn("**DACS-1 v0.8**", dacs1)
        self.assertIn("**DACS-2 v0.6**", dacs2)
        for rule in range(1, 7):
            self.assertIn(f"**(PCR-{rule})", dacs1)
        for text in (
            "It MUST NOT call a verification recipe, create a `VerifyResult`, or add a `VerifyResultRef`",
            "the reliance decision is `indeterminate` until the bundle is available",
            "aggregate(record, recordRef, requirement, authority, recipeRegistryResolver)",
            "exact_presented_satisfies_presence_member(requirement, presented):",
            "exact_selector_authorized(record, exactBundle, requirement):",
            "registry := recipeRegistryResolver.resolve_authenticated(registryVersion)",
            "cr.scheme is not a known canonical ClaimReference scheme",
            "cr.verificationRequired is not exactly the JSON boolean true or false",
            "if any group in oneOfGroups is not a non-empty array:",
        ):
            self.assertIn(text, dacs1 + dacs2)
        self.assertNotIn(
            "resolve_authenticated(registryVersion) if verifiedMembers is not empty",
            dacs2,
        )
        self.assertLess(
            dacs2.index(
                "registry := recipeRegistryResolver.resolve_authenticated(registryVersion)"
            ),
            dacs2.index(
                'if exactBundle unavailable: return "indeterminate", '
                '["exact bundle unavailable"]'
            ),
        )


if __name__ == "__main__":
    unittest.main()
