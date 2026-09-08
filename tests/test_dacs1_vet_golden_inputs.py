import base64
import copy
import hashlib
import json
import math
import re
import subprocess
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from dacs_reference import (  # noqa: E402
    SAFE_INTEGER,
    NonceLedger,
    NonceRejected,
    canonical_bytes,
    canonical_equal,
    canonical_hash,
    composite_logical_address,
    exact_safe_integer,
    parse_claim_reference,
    presentation_nonce,
)

FIXTURE = (
    ROOT / "conformance" / "fixtures" / "identity"
    / "dacs1-vet-golden-inputs-v0.1.json"
)
MANIFEST = ROOT / "conformance" / "MANIFEST.json"
GENERATOR = ROOT / "scripts" / "generate_dacs1_vet_golden_inputs.py"
BUNDLE_DOMAIN = "dacs-bundle-presentation:v1:"
RESULT_DOMAIN = "dacs-verifyresult:v1:"
RECIPE_DOMAIN = "dacs-recipe:v1:"
COMPOSITE_DOMAIN = "dacs-composite:v1:"
# This pack retains an explicit deferred-cci-lei compatibility control. It is
# not the default current v0.1 registry exported by dacs_reference.
KNOWN_SCHEMES = {
    "key", "lei", "cci-lei", "did", "finra-crd", "domain",
}
KNOWN_METHODS = {
    "verifiable-credential", "tlsnotary", "zktls",
    "consensus-backed-proxy", "oauth-attested", "evm-rpc",
    "domain-tls-control", "self-signed", "demos-gcr-domain",
}
PARSER_METHODS = {
    "verifiable-credential", "tlsnotary", "zktls",
    "consensus-backed-proxy", "evm-rpc",
}
RECIPE_AVAILABILITIES = {
    "live", "operator_gated", "closed_data", "bilateral", "mocked",
    "disabled", "failed",
}
NON_OPERATIONAL_EXPLICIT_AVAILABILITIES = {"mocked", "disabled", "failed"}
KEY = re.compile(r"^[0-9a-f]{64}$")
LEI = re.compile(r"^[0-9A-Z]{20}$")
FINRA_CRD = re.compile(r"^[1-9][0-9]*$")
DID_IDENTIFIER = re.compile(
    r"^[a-z0-9]+:[A-Za-z0-9._:%-]+(?::[A-Za-z0-9._:%-]+)*$"
)
SAFE_INT = SAFE_INTEGER


def fixture_private_key(label):
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(("dacs-363:" + label).encode("utf-8")).digest()
    )


def public_ref(key):
    value = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return f"key:{value.hex()}"


RECIPE_STEWARD_REF = public_ref(fixture_private_key("recipe-steward"))
AUTHORITY_REF = public_ref(fixture_private_key("authority"))


def hash_hex(value):
    return canonical_hash(value)


def b64url_decode(value):
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("non-canonical Base64URL")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError("non-canonical Base64URL")
    return decoded


def b64url_encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def parse_ref(value):
    parsed = parse_claim_reference(value, registered_schemes=KNOWN_SCHEMES)
    return parsed.identity


def all_safe_integers(value):
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return -SAFE_INT <= value <= SAFE_INT
    if isinstance(value, dict):
        return all(all_safe_integers(item) for item in value.values())
    if isinstance(value, list):
        return all(all_safe_integers(item) for item in value)
    return True


def verify_signature(public_ref, signature, payload):
    try:
        scheme, public_hex = parse_ref(public_ref)
        if scheme != "key":
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            b64url_decode(signature), payload
        )
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def resign_result(resolved, key, signer, domain=RESULT_DOMAIN):
    changed = copy.deepcopy(resolved)
    unsigned = {
        name: value
        for name, value in changed["artifact"].items()
        if name != "signature"
    }
    content_hash = hash_hex(unsigned)
    changed["ref"]["contentHash"] = content_hash
    changed["ref"]["recipeVersion"] = unsigned["recipeVersion"]
    changed["artifact"] = {
        **unsigned,
        "signature": {
            "algorithm": "ed25519",
            "signer": signer,
            "value": b64url_encode(
                key.sign((domain + content_hash).encode("ascii"))
            ),
        },
    }
    changed["serializedArtifactHash"] = hash_hex(changed["artifact"])
    return changed


def resign_bundle(bundle, key, signer):
    changed = copy.deepcopy(bundle)
    unsigned = {
        name: value
        for name, value in changed.items()
        if name != "presentation"
    }
    changed["presentation"] = {
        "kind": "per-claim",
        "signatures": [{
            "ref": signer,
            "signature": b64url_encode(
                key.sign(
                    (BUNDLE_DOMAIN + hash_hex(unsigned)).encode("ascii")
                )
            ),
        }],
    }
    return changed


def resign_composite_input(value):
    changed = copy.deepcopy(value)
    record = changed["record"]
    unsigned = {
        name: item for name, item in record.items() if name != "signature"
    }
    record_hash = hash_hex(unsigned)
    verifier = fixture_private_key("verifier")
    record["signature"] = {
        "algorithm": "ed25519",
        "signer": public_ref(verifier),
        "value": b64url_encode(
            verifier.sign((COMPOSITE_DOMAIN + record_hash).encode("ascii"))
        ),
    }
    changed["recordRef"]["contentHash"] = record_hash
    changed["recordRef"]["signer"] = public_ref(verifier)
    return changed


def authenticated_recipe_registry(document):
    context = document.get("trustedContext")
    registry = context.get("recipeRegistry") if isinstance(context, dict) else None
    if not isinstance(registry, dict):
        return None
    if (
        registry.get("recipeRegistryVersion") != 1
        or registry.get("steward") != RECIPE_STEWARD_REF
        or not isinstance(registry.get("recipes"), list)
    ):
        return None
    resolved = {}
    scheme_versions = set()
    for recipe in registry["recipes"]:
        if not isinstance(recipe, dict):
            return None
        signature = recipe.get("signature")
        method = recipe.get("defaultMethod")
        if (
            not isinstance(signature, dict)
            or set(signature) != {"algorithm", "signer", "value"}
            or signature.get("algorithm") != "ed25519"
            or signature.get("signer") != RECIPE_STEWARD_REF
            or not isinstance(method, dict)
        ):
            return None
        unsigned = {key: value for key, value in recipe.items() if key != "signature"}
        if not verify_signature(
            RECIPE_STEWARD_REF,
            signature.get("value"),
            (RECIPE_DOMAIN + hash_hex(unsigned)).encode("ascii"),
        ):
            return None
        scheme = recipe.get("scheme")
        kind = method.get("kind")
        version = recipe.get("recipeVersion")
        if (
            scheme not in KNOWN_SCHEMES
            or kind not in KNOWN_METHODS
            or type(version) is not int
            or version < 1
            or recipe.get("availability") not in RECIPE_AVAILABILITIES
            or recipe.get("governance", {}).get("proposedBy")
            != RECIPE_STEWARD_REF
        ):
            return None
        has_parser = isinstance(recipe.get("parserRules"), dict)
        if (kind in PARSER_METHODS) != has_parser:
            return None
        if has_parser and recipe["parserRules"] != {
            "format": "raw", "matcher": ".+"
        }:
            return None
        family_key = (scheme, kind, version)
        scheme_version = (scheme, version)
        if family_key in resolved or scheme_version in scheme_versions:
            return None
        resolved[family_key] = recipe
        scheme_versions.add(scheme_version)
    return resolved


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
        and type(value.get("recipeVersion")) is int
        and value["recipeVersion"] >= 1
    )


def well_formed_attestation_ref(value):
    if not isinstance(value, dict) or set(value) != {
        "anchor", "contentHash", "signer"
    }:
        return False
    anchor = value.get("anchor")
    try:
        signer_scheme, _ = parse_ref(value.get("signer"))
    except ValueError:
        return False
    return (
        isinstance(anchor, dict)
        and set(anchor) == {"kind", "locator"}
        and isinstance(anchor.get("kind"), str)
        and anchor.get("kind") in {"storage-program", "ipfs", "https"}
        and isinstance(anchor.get("locator"), str)
        and bool(anchor["locator"])
        and isinstance(value.get("contentHash"), str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", value["contentHash"]))
        and signer_scheme == "key"
    )


def authenticated_result_context(document, recipes):
    context = document.get("trustedContext")
    if not isinstance(context, dict) or not isinstance(recipes, dict):
        return None
    authorities = context.get("resultAuthorities")
    attestations = context.get("authenticatedSourceAttestations")
    result_artifacts = context.get("authenticatedResultArtifacts")
    if not all(
        isinstance(items, list)
        for items in (authorities, attestations, result_artifacts)
    ):
        return None

    authority_by_family = {}
    for authority in authorities:
        if not isinstance(authority, dict) or set(authority) != {
            "scheme", "method", "recipeVersion", "algorithm", "signer"
        }:
            return None
        family = (
            authority.get("scheme"),
            authority.get("method"),
            authority.get("recipeVersion"),
        )
        if (
            family not in recipes
            or authority.get("algorithm") != "ed25519"
            or authority.get("signer") != AUTHORITY_REF
            or family in authority_by_family
        ):
            return None
        authority_by_family[family] = authority
    if set(authority_by_family) != set(recipes):
        return None

    attestation_by_key = {}
    for entry in attestations:
        if not isinstance(entry, dict) or set(entry) != {
            "attestation", "scheme", "method", "recipeVersion", "resultSigner"
        }:
            return None
        family = (
            entry.get("scheme"), entry.get("method"), entry.get("recipeVersion")
        )
        attestation = entry.get("attestation")
        key = canonical_bytes(attestation)
        if (
            family not in authority_by_family
            or not well_formed_attestation_ref(attestation)
            or entry.get("resultSigner")
            != authority_by_family[family]["signer"]
            or attestation.get("signer") != entry.get("resultSigner")
            or key in attestation_by_key
        ):
            return None
        attestation_by_key[key] = entry

    result_hash_by_ref = {}
    for entry in result_artifacts:
        if not isinstance(entry, dict) or set(entry) != {
            "ref", "serializedArtifactHash"
        }:
            return None
        reference = entry.get("ref")
        key = canonical_bytes(reference)
        artifact_hash = entry.get("serializedArtifactHash")
        if (
            not well_formed_result_ref(reference)
            or not isinstance(artifact_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", artifact_hash)
            or key in result_hash_by_ref
        ):
            return None
        result_hash_by_ref[key] = artifact_hash
    return {
        "authorityByFamily": authority_by_family,
        "attestationByKey": attestation_by_key,
        "resultHashByRef": result_hash_by_ref,
    }


@dataclass(frozen=True)
class VetAdmissionCapability:
    """One verifier-owned, nonce-consuming admission for nested Vet checks."""

    invocation_id: str
    challenge_id: str
    nonce: str
    job_id: str
    actor: str
    evaluated_party: str
    primary_claim: str
    phase_index: int
    attempt: int
    expected_verifier_role: str
    expected_verifier: str
    phase_orchestrator: str
    anchor_writer: str
    recipe_registry_version: int
    trusted_now: int
    session_start: str
    record_receipt_id: str | None
    record_anchor_binding: dict | None


class VetReferenceRuntime:
    """Mutable offline runtime; caller payloads cannot reset its nonce ledger."""

    _INVOCATION_FIELDS = {
        "jobId", "sessionStart", "sessionState", "phaseKind", "phaseIndex",
        "attempt", "actor", "evaluatedParty", "primaryClaim",
        "expectedVerifierRole",
        "expectedVerifier", "phaseOrchestrator", "anchorWriter",
        "recipeRegistryVersion", "challengeId", "trustedNow",
        "recordReceiptId", "recordAnchorBinding",
    }

    def __init__(self, trusted_context):
        if not isinstance(trusted_context, dict):
            raise ValueError("trusted Vet context is missing")
        invocations = trusted_context.get("vetInvocations")
        receipts = trusted_context.get("authenticatedRecordReceipts")
        sessions = trusted_context.get("authenticatedSessionStarts")
        if (
            not isinstance(invocations, dict)
            or not isinstance(receipts, dict)
            or not isinstance(sessions, dict)
        ):
            raise ValueError("trusted Vet registries are missing")
        self.trusted_context = trusted_context
        self.invocations = invocations
        self.receipts = receipts
        self.sessions = sessions
        self.nonce_ledger = NonceLedger(
            trusted_context.get("nonceIssuances"), registered_schemes=KNOWN_SCHEMES
        )

    def _trusted_invocation(self, invocation_id):
        context = self.invocations.get(invocation_id)
        if not isinstance(context, dict) or set(context) != self._INVOCATION_FIELDS:
            return None
        if (
            context.get("sessionState") != "vet-pending"
            or context.get("phaseKind") != "vet-credentials"
            or not isinstance(context.get("actor"), str)
            or context.get("actor") not in {"buyer", "seller"}
            or not isinstance(context.get("expectedVerifierRole"), str)
            or context.get("expectedVerifierRole") not in {
                "counterparty", "orchestrator"
            }
            or not exact_safe_integer(context.get("phaseIndex"), minimum=0)
            or not exact_safe_integer(context.get("attempt"), minimum=1)
            or not exact_safe_integer(context.get("recipeRegistryVersion"), minimum=1)
            or not exact_safe_integer(context.get("trustedNow"), minimum=0)
            or not isinstance(context.get("sessionStart"), str)
            or context["sessionStart"] not in self.sessions
            or not isinstance(context.get("challengeId"), str)
        ):
            return None
        session = self.sessions[context["sessionStart"]]
        registry = self.trusted_context.get("recipeRegistry")
        if (
            not isinstance(session, dict)
            or not isinstance(registry, dict)
            or session.get("jobId") != context.get("jobId")
            or not exact_safe_integer(session.get("recipeRegistryVersion"), minimum=1)
            or not exact_safe_integer(registry.get("recipeRegistryVersion"), minimum=1)
            or session["recipeRegistryVersion"] != context["recipeRegistryVersion"]
            or registry["recipeRegistryVersion"] != context["recipeRegistryVersion"]
        ):
            return None
        try:
            for name in (
                "evaluatedParty", "primaryClaim", "expectedVerifier",
                "phaseOrchestrator", "anchorWriter",
            ):
                parse_ref(context.get(name))
        except ValueError:
            return None
        if context["primaryClaim"] != context["evaluatedParty"]:
            return None
        if (
            context["expectedVerifierRole"] == "orchestrator"
            and context["expectedVerifier"] != context["phaseOrchestrator"]
        ):
            return None
        receipt_id = context.get("recordReceiptId")
        binding = context.get("recordAnchorBinding")
        if (receipt_id is None) != (binding is None):
            return None
        if receipt_id is not None and (
            not isinstance(receipt_id, str)
            or receipt_id not in self.receipts
            or not isinstance(binding, dict)
        ):
            return None
        return context

    def admit(self, authority, bundle):
        if not isinstance(authority, dict):
            return None
        invocation_id = authority.get("invocation")
        if not isinstance(invocation_id, str):
            return None
        context = self._trusted_invocation(invocation_id)
        if context is None:
            return None
        try:
            # SN-4 consumption deliberately precedes all candidate-controlled
            # bundle, actor, record, signature, and requirement checks.
            issuance = self.nonce_ledger.consume(
                context["challengeId"],
                presentation_nonce(bundle),
                context["trustedNow"],
            )
        except NonceRejected:
            return None
        if (
            issuance.job_id != context["jobId"]
            or issuance.actor != context["actor"]
            or issuance.evaluated_party != context["evaluatedParty"]
            or issuance.phase_index != context["phaseIndex"]
            or issuance.attempt != context["attempt"]
            or issuance.expected_verifier != context["expectedVerifier"]
            or issuance.issued_by != context["expectedVerifier"]
            or not isinstance(bundle, dict)
            or bundle.get("presentedBy") != context["primaryClaim"]
        ):
            return None
        return VetAdmissionCapability(
            invocation_id,
            context["challengeId"],
            issuance.nonce,
            context["jobId"],
            context["actor"],
            context["evaluatedParty"],
            context["primaryClaim"],
            context["phaseIndex"],
            context["attempt"],
            context["expectedVerifierRole"],
            context["expectedVerifier"],
            context["phaseOrchestrator"],
            context["anchorWriter"],
            context["recipeRegistryVersion"],
            context["trustedNow"],
            context["sessionStart"],
            context["recordReceiptId"],
            copy.deepcopy(context["recordAnchorBinding"]),
        )


def verify_bundle(bundle, admission=None):
    if not isinstance(bundle, dict) or not all_safe_integers(bundle):
        return False
    if set(bundle) - {
        "bundleVersion", "presentedBy", "presentedAt", "sessionNonce",
        "claims", "presentation",
    }:
        return False
    if not {
        "bundleVersion", "presentedBy", "presentedAt", "claims", "presentation"
    } <= set(bundle):
        return False
    if (
        bundle.get("bundleVersion") != "1"
        or not exact_safe_integer(bundle.get("presentedAt"), minimum=0)
        or (
            admission is not None
            and presentation_nonce(bundle) != admission.nonce
        )
    ):
        return False
    claims = bundle.get("claims")
    if (
        not isinstance(claims, list)
        or not claims
        or any(not isinstance(item, dict) for item in claims)
    ):
        return False
    try:
        canonical_presented = parse_ref(bundle.get("presentedBy"))
        parsed_claims = [parse_ref(item.get("ref")) for item in claims]
    except (AttributeError, ValueError):
        return False
    if canonical_presented not in parsed_claims:
        return False
    presentation = bundle.get("presentation")
    if not isinstance(presentation, dict) or set(presentation) != {
        "kind", "signatures"
    } or presentation.get("kind") != "per-claim":
        return False
    signatures = presentation.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return False
    unsigned = {key: value for key, value in bundle.items() if key != "presentation"}
    try:
        payload = (BUNDLE_DOMAIN + hash_hex(unsigned)).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        return False
    claim_refs = {item["ref"] for item in claims}
    return all(
        isinstance(item, dict)
        and set(item) == {"ref", "signature"}
        and isinstance(item.get("ref"), str)
        and item.get("ref") in claim_refs
        and verify_signature(item["ref"], item.get("signature"), payload)
        for item in signatures
    )


def verify_result(resolved, recipes, result_context):
    if (
        not isinstance(resolved, dict)
        or set(resolved) != {"ref", "artifact", "serializedArtifactHash"}
        or not isinstance(result_context, dict)
    ):
        return False
    artifact = resolved.get("artifact")
    reference = resolved.get("ref")
    if not well_formed_result_ref(reference) or not isinstance(artifact, dict):
        return False
    signature = artifact.get("signature")
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm", "signer", "value"
    } or signature.get("algorithm") != "ed25519" or not isinstance(
        signature.get("signer"), str
    ):
        return False
    if (
        not isinstance(artifact.get("scheme"), str)
        or not isinstance(artifact.get("method"), str)
        or type(artifact.get("recipeVersion")) not in (int, float)
    ):
        return False
    unsigned = {key: value for key, value in artifact.items() if key != "signature"}
    try:
        unsigned_hash = hash_hex(unsigned)
        full_hash = hash_hex(artifact)
        reference_key = canonical_bytes(reference)
        attestation_key = canonical_bytes(artifact.get("attestation"))
    except (TypeError, ValueError, UnicodeError):
        return False
    if unsigned_hash != reference["contentHash"]:
        return False
    method = artifact.get("method")
    family = (
        artifact.get("scheme"), method, artifact.get("recipeVersion")
    )
    if method not in KNOWN_METHODS or not isinstance(recipes, dict):
        return False
    recipe = recipes.get(family)
    if recipe is None:
        return False
    issuer_allow_list = recipe["defaultMethod"].get("issuerAllowList")
    if (
        method == "verifiable-credential"
        and issuer_allow_list is not None
        and signature.get("signer") not in issuer_allow_list
    ):
        return False
    authority = result_context["authorityByFamily"].get(family)
    authenticated_full_hash = result_context["resultHashByRef"].get(
        reference_key
    )
    source_attestation = result_context["attestationByKey"].get(
        attestation_key
    )
    try:
        canonical_identity = parse_ref(
            f"{artifact.get('scheme')}:{artifact.get('identifier')}"
        )
    except ValueError:
        return False
    if (
        canonical_identity
        != (artifact.get("scheme"), artifact.get("identifier"))
        or authority is None
        or signature.get("signer") != authority["signer"]
        or signature.get("algorithm") != authority["algorithm"]
        or not well_formed_attestation_ref(artifact.get("attestation"))
        or source_attestation is None
        or (
            source_attestation["scheme"],
            source_attestation["method"],
            source_attestation["recipeVersion"],
        ) != family
        or source_attestation["resultSigner"] != authority["signer"]
        or resolved.get("serializedArtifactHash") != full_hash
        or authenticated_full_hash != full_hash
        or not exact_safe_integer(artifact.get("fetchedAt"), minimum=0)
        or not exact_safe_integer(artifact.get("verifiedAt"), minimum=0)
        or not exact_safe_integer(artifact.get("validUntil"), minimum=0)
        or artifact["fetchedAt"] > artifact["verifiedAt"]
        or artifact["verifiedAt"] > artifact["validUntil"]
    ):
        return False
    return verify_signature(
        authority["signer"],
        signature.get("value"),
        (RESULT_DOMAIN + unsigned_hash).encode("ascii"),
    )


def resolved_by_ref(value):
    items = value.get("resolvedResults")
    if not isinstance(items, list):
        return None
    resolved = {}
    for item in items:
        if not isinstance(item, dict) or not well_formed_result_ref(item.get("ref")):
            return None
        key = canonical_bytes(item["ref"])
        if key in resolved:
            return None
        resolved[key] = item
    return resolved


def matching_claims(value, req, decision_time, exact_ref=None):
    now = decision_time
    matches = []
    for item in value["bundle"]["claims"]:
        scheme, _ = parse_ref(item.get("ref"))
        if scheme != req.get("scheme"):
            continue
        if exact_ref is not None and item.get("ref") != exact_ref:
            continue
        expires_at = item.get("expiresAt")
        if expires_at is not None and (
            type(expires_at) is not int or now > expires_at
        ):
            continue
        parameters = req.get("parameters")
        if req.get("verificationRequired") is False and parameters is not None:
            metadata = item.get("metadata")
            if not isinstance(metadata, dict) or any(
                key not in metadata
                or canonical_bytes(metadata[key]) != canonical_bytes(required)
                for key, required in parameters.items()
            ):
                continue
        matches.append(item)
    return matches


def effective_recipe_version(req, method, recipes):
    if not isinstance(method, str) or not method or not isinstance(recipes, dict):
        return None
    family = sorted(
        version
        for scheme, family_method, version in recipes
        if scheme == req.get("scheme") and family_method == method
    )
    if not family:
        return None
    if "recipeVersion" in req:
        expected = req["recipeVersion"]
        recipe = recipes.get((req.get("scheme"), method, expected))
        if (
            recipe is None
            or recipe.get("availability")
            in NON_OPERATIONAL_EXPLICIT_AVAILABILITIES
        ):
            return None
        return expected
    expected = family[-1]
    recipe = recipes.get((req.get("scheme"), method, expected))
    if recipe is None or recipe.get("availability") != "live":
        return None
    return expected


def parameters_match(result, req):
    parameters = req.get("parameters")
    if parameters is None:
        return True
    method = parameters.get("verificationMethod")
    if method is not None and result.get("method") != method:
        return False
    required_data = {
        key: value
        for key, value in parameters.items()
        if key != "verificationMethod"
    }
    if not required_data:
        return True
    data = result.get("data")
    return isinstance(data, dict) and all(
        key in data
        and canonical_bytes(data[key]) == canonical_bytes(required)
        for key, required in required_data.items()
    )


def result_outcome(value, claim, req, recipes, result_context, decision_time):
    reference = claim.get("verifiedBy")
    if not well_formed_result_ref(reference):
        return "fail" if reference is None else "error"
    results = resolved_by_ref(value)
    if results is None:
        return "error"
    resolved = results.get(canonical_bytes(reference))
    if resolved is None:
        return "indeterminate"
    if not verify_result(resolved, recipes, result_context):
        return "error"
    result = resolved["artifact"]
    scheme, identifier = parse_ref(claim["ref"])
    if (
        result.get("scheme") != scheme
        or result.get("identifier") != identifier
        or result.get("recipeVersion") != reference["recipeVersion"]
    ):
        return "fail"
    parameters = req.get("parameters") or {}
    selected_method = parameters.get("verificationMethod", result.get("method"))
    expected_version = effective_recipe_version(req, selected_method, recipes)
    if expected_version is None:
        return "qualification-error"
    if (
        result.get("method") != selected_method
        or result.get("recipeVersion") != expected_version
    ):
        return "not-applicable"
    decision = result.get("decision")
    if not isinstance(decision, str) or decision not in {
        "pass", "fail", "indeterminate", "error"
    }:
        return "error"
    verified_at = result.get("verifiedAt")
    valid_until = result.get("validUntil")
    if type(verified_at) is not int or type(valid_until) is not int:
        return "fail"
    now = decision_time
    expires_at = claim.get("expiresAt")
    effective_expiry = min(
        valid_until,
        expires_at if type(expires_at) is int else SAFE_INT,
    )
    if verified_at > now:
        return "error"
    if now > effective_expiry:
        return "not-applicable"
    max_age = req.get("maxAge")
    if max_age is not None and now > verified_at + max_age * 1_000:
        return "not-applicable"
    if decision == "pass" and not parameters_match(result, req):
        return "fail"
    return decision


def classify_member(
    value, req, recipes, result_context, decision_time, exact_ref=None
):
    matches = matching_claims(value, req, decision_time, exact_ref)
    if req.get("verificationRequired") is False:
        return "pass" if matches else "fail"
    parameters = req.get("parameters") or {}
    selected_method = parameters.get("verificationMethod")
    if (
        selected_method is not None
        and effective_recipe_version(req, selected_method, recipes) is None
    ):
        return "error"
    outcomes = [
        result_outcome(
            value, item, req, recipes, result_context, decision_time
        )
        for item in matches
    ]
    if "qualification-error" in outcomes:
        return "error"
    for outcome in ("pass", "fail", "error", "indeterminate"):
        if outcome in outcomes:
            return outcome
    return "fail"


def qualification_preflight(
    value, req, recipes, result_context, decision_time
):
    if req.get("verificationRequired") is False:
        return True
    parameters = req.get("parameters") or {}
    selected_method = parameters.get("verificationMethod")
    if (
        selected_method is not None
        and effective_recipe_version(req, selected_method, recipes) is None
    ):
        return False
    return all(
        result_outcome(
            value, claim, req, recipes, result_context, decision_time
        )
        != "qualification-error"
        for claim in matching_claims(value, req, decision_time)
    )


def presented_control(value, recipes, result_context, decision_time):
    bundle = value["bundle"]
    presented = bundle["presentedBy"]
    scheme, _ = parse_ref(presented)
    claim = next(item for item in bundle["claims"] if item["ref"] == presented)
    signer_refs = {
        item["ref"] for item in bundle["presentation"]["signatures"]
    }
    if scheme == "key":
        return presented in signer_refs
    reference = claim.get("verifiedBy")
    if not well_formed_result_ref(reference):
        return False
    results = resolved_by_ref(value)
    if results is None:
        return False
    resolved = results.get(canonical_bytes(reference))
    if resolved is None or not verify_result(resolved, recipes, result_context):
        return False
    result = resolved["artifact"]
    binding = result.get("data", {}).get("holderBinding")
    return (
        result_outcome(
            value,
            claim,
            {"scheme": scheme, "verificationRequired": True,
             "recipeVersion": reference["recipeVersion"]},
            recipes,
            result_context,
            decision_time,
        ) == "pass"
        and result.get("method") == "verifiable-credential"
        and isinstance(binding, dict)
        and binding.get("controller") in signer_refs
    )


def selector_authorized(value, req, recipes, result_context, decision_time):
    selector = req.get("primaryClaimSelector")
    if selector is None:
        return True
    bundle = value["bundle"]
    scheme, _ = parse_ref(bundle["presentedBy"])
    if scheme != selector or not presented_control(
        value, recipes, result_context, decision_time
    ):
        return False
    required = req.get("required", [])
    one_of = req.get("oneOf", [])
    if any(
        item.get("scheme") == selector
        and item.get("verificationRequired") is True
        for item in required
    ):
        selected_req = next(
            item for item in required
            if item.get("scheme") == selector
            and item.get("verificationRequired") is True
        )
        return classify_member(
            value, selected_req, recipes, result_context, decision_time,
            exact_ref=bundle["presentedBy"]
        ) == "pass"
    presence_members = [
        item for item in required
        if item.get("scheme") == selector
        and item.get("verificationRequired") is False
    ]
    if any(
        classify_member(
            value, item, recipes, result_context, decision_time,
            exact_ref=bundle["presentedBy"]
        ) == "pass"
        for item in presence_members
    ):
        return True
    for group in one_of:
        if any(
            item.get("scheme") == selector
            and item.get("verificationRequired") is False
            and classify_member(
                value, item, recipes, result_context, decision_time,
                exact_ref=bundle["presentedBy"]
            ) == "pass"
            for item in group
        ):
            return True
    return False


def valid_requirement(req):
    try:
        canonical_bytes(req)
    except (TypeError, ValueError, UnicodeError):
        return False
    if (
        not isinstance(req, dict)
        or req.get("requirementVersion") != "1"
        or not all_safe_integers(req)
    ):
        return False
    required = req.get("required")
    one_of = req.get("oneOf", [])
    if not isinstance(required, list) or not isinstance(one_of, list):
        return False
    if any(not isinstance(group, list) or not group for group in one_of):
        return False
    for item in [*required, *(member for group in one_of for member in group)]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("scheme"), str)
            or item.get("scheme") not in KNOWN_SCHEMES
            or type(item.get("verificationRequired")) is not bool
            or (
                "recipeVersion" in item
                and (
                    type(item["recipeVersion"]) is not int
                    or not 1 <= item["recipeVersion"] <= SAFE_INT
                )
            )
            or (
                "maxAge" in item
                and (
                    type(item["maxAge"]) is not int
                    or not 0 <= item["maxAge"] <= SAFE_INT
                )
            )
            or (
                item.get("verificationRequired") is False
                and ("maxAge" in item or "recipeVersion" in item)
            )
            or (
                "parameters" in item
                and (
                    not isinstance(item["parameters"], dict)
                    or any(
                        not isinstance(key, str) or not key
                        for key in item["parameters"]
                    )
                    or (
                        "verificationMethod" in item["parameters"]
                        and (
                            not isinstance(
                                item["parameters"]["verificationMethod"], str
                            )
                            or not item["parameters"]["verificationMethod"]
                        )
                    )
                )
            )
        ):
            return False
    return True


def valid_supplementary_signals(signals):
    if not isinstance(signals, list):
        return False
    for signal in signals:
        if (
            not isinstance(signal, dict)
            or not {"source", "signalType", "value", "observedAt"} <= set(signal)
            or set(signal) - {
                "source", "signalType", "value", "observedAt", "attestation"
            }
            or not isinstance(signal.get("source"), str)
            or not signal["source"]
            or not isinstance(signal.get("signalType"), str)
            or not signal["signalType"]
            or isinstance(signal.get("value"), bool)
            or not isinstance(signal.get("value"), (int, float, str))
            or (
                type(signal.get("value")) is int
                and not -SAFE_INT <= signal["value"] <= SAFE_INT
            )
            or (
                type(signal.get("value")) is float
                and not math.isfinite(signal["value"])
            )
            or type(signal.get("observedAt")) is not int
            or not 0 <= signal["observedAt"] <= SAFE_INT
            or (
                signal.get("source") == "external"
                and not well_formed_attestation_ref(signal.get("attestation"))
            )
            or (
                "attestation" in signal
                and not well_formed_attestation_ref(signal["attestation"])
            )
        ):
            return False
    return True


def evaluate(value, recipes, result_context, *, decision_time, admission):
    if (
        not isinstance(value, dict)
        or not exact_safe_integer(decision_time, minimum=0)
        or not isinstance(admission, VetAdmissionCapability)
    ):
        return "error", ["invalid evaluation time"]
    if not verify_bundle(value.get("bundle"), admission):
        return "error", ["invalid identity bundle"]
    req = value.get("requirement")
    if not valid_requirement(req):
        return "error", ["invalid bundle requirement"]
    for item in value["bundle"]["claims"]:
        if "verifiedBy" in item and not well_formed_result_ref(item["verifiedBy"]):
            return "error", ["malformed verification reference"]
    if resolved_by_ref(value) is None:
        return "error", ["duplicate or malformed resolved result reference"]
    members = [
        *req.get("required", []),
        *(member for group in req.get("oneOf", []) for member in group),
    ]
    if any(
        not qualification_preflight(
            value, member, recipes, result_context, decision_time
        )
        for member in members
    ):
        return "error", ["unresolved recipe family or version"]
    failures = []
    errors = []
    indeterminates = []
    for item in req.get("required", []):
        outcome = classify_member(
            value, item, recipes, result_context, decision_time
        )
        if outcome == "fail":
            failures.append("required failing or absent: " + item["scheme"])
        elif outcome == "error":
            errors.append("required errored: " + item["scheme"])
        elif outcome == "indeterminate":
            indeterminates.append("required indeterminate: " + item["scheme"])
    for group in req.get("oneOf", []):
        outcomes = [
            classify_member(
                value, item, recipes, result_context, decision_time
            )
            for item in group
        ]
        if "pass" in outcomes:
            continue
        if "error" in outcomes:
            errors.append("oneOf group: at least one claim errored")
        elif "indeterminate" in outcomes:
            indeterminates.append(
                "oneOf group: at least one claim indeterminate"
            )
        else:
            failures.append("oneOf group: no claim satisfied")
    if not selector_authorized(
        value, req, recipes, result_context, decision_time
    ):
        failures.append(
            "primaryClaimSelector is mismatched, uncontrolled, or unauthorized"
        )
    if failures:
        return "fail", failures
    if errors:
        return "error", errors
    if indeterminates:
        return "indeterminate", indeterminates
    return "pass", []


def evaluate_decision(
    value, recipes, result_context, *, decision_time, admission
):
    return evaluate(
        value,
        recipes,
        result_context,
        decision_time=decision_time,
        admission=admission,
    )[0]


def well_formed_record_ref(value):
    if not isinstance(value, dict) or set(value) != {
        "anchor", "contentHash", "signer"
    }:
        return False
    anchor = value.get("anchor")
    try:
        signer = parse_ref(value.get("signer"))
    except ValueError:
        return False
    return (
        isinstance(anchor, dict)
        and set(anchor) == {"kind", "locator"}
        and isinstance(anchor.get("kind"), str)
        and anchor.get("kind") in {"storage-program", "ipfs", "https"}
        and isinstance(anchor.get("locator"), str)
        and bool(anchor["locator"])
        and isinstance(value.get("contentHash"), str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", value["contentHash"]))
        and signer[0] == "key"
    )


def authenticated_record_time(
    record, record_ref, admission, runtime, *, terminal_replay=False
):
    """Validate the independent logical/native SR-2 receipt binding."""

    receipt = runtime.receipts.get(admission.record_receipt_id)
    binding = admission.record_anchor_binding
    if not isinstance(receipt, dict) or not isinstance(binding, dict):
        return None
    if set(binding) != {
        "anchorKind", "logicalAddress", "nativeAddress", "writer"
    }:
        return None
    required = {
        "receiptVersion", "substrate", "finalityProfile", "logicalAddress",
        "nativeAddress", "contentHash", "transactionRef", "writer", "state",
        "observationDisposition", "observedAt", "evidence",
    }
    if not required <= set(receipt) or set(receipt) - (required | {"blockRef"}):
        return None
    anchor = record_ref.get("anchor")
    try:
        expected_logical = composite_logical_address(
            record.get("jobId"), record.get("evaluatedParty")
        )
        parse_ref(receipt.get("writer"))
    except ValueError:
        return None
    if (
        receipt.get("receiptVersion") != "1"
        or not isinstance(receipt.get("substrate"), str)
        or not receipt["substrate"]
        or not isinstance(receipt.get("finalityProfile"), str)
        or not receipt["finalityProfile"]
        or not isinstance(receipt.get("logicalAddress"), str)
        or not isinstance(receipt.get("nativeAddress"), str)
        or not receipt["nativeAddress"]
        or not isinstance(receipt.get("contentHash"), str)
        or receipt.get("observationDisposition") != "established"
        or receipt.get("state") not in {"accepted", "included", "finalized"}
        or (terminal_replay and receipt.get("state") != "finalized")
        or binding.get("anchorKind") != anchor.get("kind")
        or not isinstance(binding.get("anchorKind"), str)
        or binding.get("logicalAddress") != expected_logical
        or receipt.get("logicalAddress") != expected_logical
        or binding.get("nativeAddress") != anchor.get("locator")
        or receipt.get("nativeAddress") != anchor.get("locator")
        or receipt.get("nativeAddress") == receipt.get("logicalAddress")
        or binding.get("writer") != admission.anchor_writer
        or receipt.get("writer") != admission.anchor_writer
        or receipt.get("contentHash") != record_ref.get("contentHash")
    ):
        return None
    transaction_ref = receipt.get("transactionRef")
    evidence = receipt.get("evidence")
    if not all(
        isinstance(item, dict)
        and set(item) == {"kind", "value"}
        and isinstance(item.get("kind"), str)
        and bool(item["kind"])
        and isinstance(item.get("value"), str)
        and bool(item["value"])
        for item in (transaction_ref, evidence)
    ):
        return None
    observed_at = receipt.get("observedAt")
    if (
        not exact_safe_integer(observed_at, minimum=0)
        or observed_at > admission.trusted_now
    ):
        return None
    receipt_time = observed_at
    if receipt["state"] in {"included", "finalized"}:
        block_ref = receipt.get("blockRef")
        if (
            not isinstance(block_ref, dict)
            or not {"id", "timestamp"} <= set(block_ref)
            or set(block_ref) - {"id", "height", "timestamp"}
            or not isinstance(block_ref.get("id"), str)
            or not block_ref["id"]
            or not exact_safe_integer(block_ref.get("timestamp"), minimum=0)
            or block_ref["timestamp"] > observed_at
            or (
                "height" in block_ref
                and (
                    not isinstance(block_ref["height"], str)
                    or re.fullmatch(r"0|[1-9][0-9]*", block_ref["height"]) is None
                )
            )
        ):
            return None
        receipt_time = block_ref["timestamp"]
    return receipt_time


def authenticate_production_aggregate(
    value, trusted_context, recipes, result_context, admission, runtime
):
    if not isinstance(value, dict) or not isinstance(trusted_context, dict):
        return None
    record = value.get("record")
    record_ref = value.get("recordRef")
    authority = value.get("authority")
    if (
        not isinstance(record, dict)
        or not well_formed_record_ref(record_ref)
        or not isinstance(authority, dict)
        or set(authority) != {
            "kind", "invocation", "authenticatedSessionStart", "vetInput"
        }
        or authority.get("kind") != "production"
        or authority.get("invocation") != admission.invocation_id
    ):
        return None
    signature = record.get("signature")
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "signer", "value"}
        or signature.get("algorithm") != "ed25519"
        or signature.get("signer") != record_ref.get("signer")
        or signature.get("signer") != admission.expected_verifier
    ):
        return None
    unsigned_record = {
        key: item for key, item in record.items() if key != "signature"
    }
    try:
        record_hash = hash_hex(unsigned_record)
    except (TypeError, ValueError, UnicodeError):
        return None
    if (
        record_ref.get("contentHash") != record_hash
        or not verify_signature(
            signature.get("signer"),
            signature.get("value"),
            (COMPOSITE_DOMAIN + record_hash).encode("ascii"),
        )
    ):
        return None

    vet_input = authority.get("vetInput")
    session_name = authority.get("authenticatedSessionStart")
    sessions = trusted_context.get("authenticatedSessionStarts")
    authenticated_session = (
        sessions.get(session_name)
        if isinstance(sessions, dict) and isinstance(session_name, str)
        else None
    )
    if (
        not isinstance(vet_input, dict)
        or set(vet_input) != {
            "jobId", "actor", "bundleToVet", "requirement",
            "verifierIdentity", "sessionContext", "recipeRegistryVersion",
            "attempt",
        }
        or not isinstance(authenticated_session, dict)
    ):
        return None
    session_context = vet_input.get("sessionContext")
    job_id = record.get("jobId")
    registry_version = authenticated_session.get("recipeRegistryVersion")
    if (
        not isinstance(session_context, dict)
        or not canonical_equal(session_context, authenticated_session)
        or session_name != admission.session_start
        or vet_input.get("jobId") != job_id
        or session_context.get("jobId") != job_id
        or job_id != admission.job_id
        or vet_input.get("actor") != admission.actor
        or vet_input.get("attempt") != admission.attempt
        or vet_input.get("recipeRegistryVersion") != registry_version
        or registry_version != admission.recipe_registry_version
        or trusted_context.get("recipeRegistry", {}).get(
            "recipeRegistryVersion"
        ) != registry_version
        or not isinstance(recipes, dict)
    ):
        return None

    bundle = vet_input.get("bundleToVet")
    req = vet_input.get("requirement")
    verifier_identity = vet_input.get("verifierIdentity")
    generated_at = record.get("generatedAt")
    try:
        bound_bundle_hash = hash_hex({
            key: item for key, item in bundle.items() if key != "presentation"
        })
        requirement_hash = hash_hex(req)
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return None
    if (
        not verify_bundle(bundle, admission)
        or not verify_bundle(verifier_identity, admission)
        or verifier_identity.get("presentedBy") != admission.expected_verifier
        or signature.get("signer") != admission.expected_verifier
        or record_ref.get("signer") != admission.expected_verifier
        or record.get("evaluatedParty") != admission.evaluated_party
        or record.get("evaluatedParty") != bundle.get("presentedBy")
        or record.get("bundleHash") != bound_bundle_hash
        or record.get("requirementHash") != requirement_hash
        or not exact_safe_integer(generated_at, minimum=0)
        or generated_at > admission.trusted_now
    ):
        return None
    receipt_time = authenticated_record_time(
        record, record_ref, admission, runtime
    )
    if receipt_time is None or generated_at > receipt_time:
        return None

    committed = record.get("freshness")
    supplementary = record.get("supplementary")
    deal_specific = record.get("dealSpecific")
    resolved = value.get("resolvedResults")
    if (
        not isinstance(committed, list)
        or not valid_supplementary_signals(supplementary)
        or not isinstance(deal_specific, list)
        or not isinstance(resolved, list)
        or any(
            signal["observedAt"] > generated_at
            for signal in supplementary
        )
    ):
        return None
    committed = committed + deal_specific
    resolved_refs = [item.get("ref") for item in resolved if isinstance(item, dict)]
    try:
        canonical_refs = [canonical_bytes(item) for item in committed]
        resolved_ref_keys = [canonical_bytes(item) for item in resolved_refs]
    except (TypeError, ValueError, UnicodeError):
        return None
    if (
        len(resolved_refs) != len(resolved)
        or resolved_ref_keys != canonical_refs
        or len(set(canonical_refs)) != len(canonical_refs)
        or any(
            not verify_result(item, recipes, result_context)
            for item in resolved
        )
        or any(
            item["artifact"]["verifiedAt"] > generated_at
            for item in resolved
        )
    ):
        return None
    return {
        "bundle": bundle,
        "requirement": req,
        "resolvedResults": resolved,
        "decisionTime": generated_at,
    }


def aggregate_output(value, trusted_context, recipes, result_context, runtime):
    try:
        if (
            not isinstance(runtime, VetReferenceRuntime)
            or runtime.trusted_context is not trusted_context
        ):
            raise ValueError("a verifier-owned runtime is required")
        active_runtime = runtime
        authority = value.get("authority") if isinstance(value, dict) else None
        vet_input = authority.get("vetInput") if isinstance(authority, dict) else None
        bundle = vet_input.get("bundleToVet") if isinstance(vet_input, dict) else None
        admission = active_runtime.admit(authority, bundle)
    except (AttributeError, TypeError, ValueError, UnicodeError):
        admission = None
    if admission is None:
        return {"decision": "error", "reasons": ["aggregation authority invalid"]}
    try:
        projection = authenticate_production_aggregate(
            value,
            trusted_context,
            recipes,
            result_context,
            admission,
            active_runtime,
        )
    except (KeyError, TypeError, ValueError, UnicodeError):
        projection = None
    if projection is None:
        return {"decision": "error", "reasons": ["aggregation authority invalid"]}
    try:
        decision, reasons = evaluate(
            projection,
            recipes,
            result_context,
            decision_time=projection["decisionTime"],
            admission=admission,
        )
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError):
        return {"decision": "error", "reasons": ["invalid aggregation input"]}
    if value["record"].get("overallDecision") != decision:
        return {
            "decision": "error",
            "reasons": ["signed overallDecision does not match replay"],
        }
    return {"decision": decision, "reasons": reasons}


def vpc4_error_class(decision, *, counterparty_malformed=False):
    if decision == "fail":
        return "counterparty"
    if decision in {"error", "indeterminate"}:
        return "counterparty" if counterparty_malformed else "permanent"
    return None


def execute(evaluation, document, runtime):
    operation = evaluation.get("operation") if isinstance(evaluation, dict) else None
    try:
        value = evaluation["input"]
        trusted_context = document["trustedContext"]
        if (
            not isinstance(runtime, VetReferenceRuntime)
            or runtime.trusted_context is not trusted_context
        ):
            raise ValueError("a verifier-owned runtime is required")
        active_runtime = runtime
        recipes = authenticated_recipe_registry(document)
        result_context = authenticated_result_context(document, recipes)
        if operation == "aggregate":
            return aggregate_output(
                value,
                trusted_context,
                recipes,
                result_context,
                runtime=active_runtime,
            )
        authority = value.get("authority") if isinstance(value, dict) else None
        if (
            not isinstance(authority, dict)
            or set(authority) != {"kind", "invocation"}
            or authority.get("kind") != "vet-invocation"
        ):
            admission = None
        else:
            admission = active_runtime.admit(authority, value.get("bundle"))
        if admission is None:
            decision = "error"
        elif operation == "control-decision":
            if not verify_bundle(value.get("bundle"), admission):
                decision = "error"
            else:
                decision = (
                    "pass"
                    if presented_control(
                        value, recipes, result_context, admission.trusted_now
                    )
                    else "fail"
                )
        else:
            decision = evaluate_decision(
                value,
                recipes,
                result_context,
                decision_time=admission.trusted_now,
                admission=admission,
            )
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError):
        decision = "error"

    if operation == "match":
        return decision == "pass"
    if operation == "decision":
        return decision
    if operation == "decision-no-throw":
        return {"decision": decision, "throws": False}
    if operation == "control-decision":
        return decision
    if operation == "aggregate":
        return {"decision": "error", "reasons": ["aggregation authority invalid"]}
    raise AssertionError(f"unknown operation {operation!r}")


def execute_once(evaluation, document):
    """Fixture helper that explicitly initializes one isolated trusted runtime."""

    runtime = VetReferenceRuntime(document["trustedContext"])
    return execute(evaluation, document, runtime=runtime)


def execute_case(case, document):
    runtime = VetReferenceRuntime(document["trustedContext"])
    observed = {
        name: execute(evaluation, document, runtime=runtime)
        for name, evaluation in case["evaluations"].items()
    }
    return observed["result"] if list(observed) == ["result"] else observed


class Dacs1VetGoldenInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = FIXTURE.read_bytes()
        cls.document = json.loads(cls.raw)
        cls.cases = cls.document["cases"]
        cls.recipes = authenticated_recipe_registry(cls.document)
        cls.result_context = authenticated_result_context(
            cls.document, cls.recipes
        )

    def test_generator_is_deterministic(self):
        subprocess.run(
            ["python3", str(GENERATOR), "--check"], cwd=ROOT, check=True
        )

    def test_count_set_hash_names_and_input_hashes(self):
        self.assertEqual("dacs1-vet-golden-inputs-v0.1", self.document["set"])
        self.assertEqual(30, self.document["count"])
        self.assertEqual(30, len(self.cases))
        self.assertEqual(30, len({case["name"] for case in self.cases}))
        self.assertEqual(self.document["hash"], hash_hex(self.cases))
        for case in self.cases:
            with self.subTest(case=case["name"]):
                self.assertEqual(
                    case["inputHash"],
                    hash_hex({"evaluations": case["evaluations"]}),
                )

    def test_every_complete_input_replays_to_expected_output(self):
        for case in self.cases:
            with self.subTest(case=case["name"]):
                self.assertEqual(
                    case["expectedOutput"], execute_case(case, self.document)
                )

    def test_manifest_binds_exact_file_cases_and_outputs(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        binding = manifest["inputBindings"][self.document["set"]]
        self.assertEqual(str(FIXTURE.relative_to(ROOT)), binding["path"])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), binding["sha256"])
        self.assertEqual(30, binding["caseCount"])
        fixture_by_name = {case["name"]: case for case in self.cases}
        manifest_cases = {
            case["id"]: case
            for case in manifest["cases"]
            if case["id"] in fixture_by_name
        }
        self.assertEqual(set(fixture_by_name), set(manifest_cases))
        for name, case in fixture_by_name.items():
            with self.subTest(case=name):
                self.assertEqual(case["expectedOutput"], manifest_cases[name]["want"])

    def test_all_non_malformed_bundles_and_all_results_are_genuinely_signed(self):
        for case in self.cases:
            for label, evaluation in case["evaluations"].items():
                with self.subTest(case=case["name"], evaluation=label):
                    value = evaluation["input"]
                    bundle = (
                        value["authority"]["vetInput"]["bundleToVet"]
                        if evaluation["operation"] == "aggregate"
                        else value["bundle"]
                    )
                    bundle_ok = verify_bundle(bundle)
                    if case["name"] == "vet-control-key-malformed-scope-reject-no-throw":
                        self.assertFalse(bundle_ok)
                    else:
                        self.assertTrue(bundle_ok)
                    for resolved in value["resolvedResults"]:
                        self.assertTrue(
                            verify_result(
                                resolved, self.recipes, self.result_context
                            )
                        )

    def test_recipe_registry_is_signed_closed_and_family_qualified(self):
        self.assertIsNotNone(self.recipes)
        self.assertEqual(7, len(self.recipes))
        self.assertEqual(
            {
                "consensus-backed-proxy", "demos-gcr-domain",
                "self-signed", "verifiable-credential",
            },
            {
                result["artifact"]["method"]
                for case in self.cases
                for evaluation in case["evaluations"].values()
                for result in evaluation["input"]["resolvedResults"]
            },
        )

    def test_crq2_regression_cases_are_manifest_bound(self):
        names = {case["name"] for case in self.cases}
        self.assertLessEqual({
            "vet-crq2-implicit-latest-family-version",
            "vet-crq2-metadata-only-parameter-rejected",
            "vet-crq2-selected-method-excludes-other-family",
            "vet-crq2-malformed-requirement-fields",
            "vet-crq2-unresolved-family-or-version-errors",
            "vet-crq2-preflight-cannot-be-masked",
        }, names)

    def test_signed_unknown_or_unregistered_family_method_is_rejected(self):
        resolved = next(
            result
            for case in self.cases
            for evaluation in case["evaluations"].values()
            for result in evaluation["input"]["resolvedResults"]
        )
        authority = fixture_private_key("authority")
        for method in ("vc-presentation", "tlsnotary"):
            with self.subTest(method=method):
                changed = json.loads(json.dumps(resolved))
                unsigned = {
                    key: value
                    for key, value in changed["artifact"].items()
                    if key != "signature"
                }
                unsigned["method"] = method
                content_hash = hash_hex(unsigned)
                changed["artifact"] = {
                    **unsigned,
                    "signature": {
                        **changed["artifact"]["signature"],
                        "value": base64.urlsafe_b64encode(
                            authority.sign(
                                (RESULT_DOMAIN + content_hash).encode("ascii")
                            )
                        ).rstrip(b"=").decode("ascii"),
                    },
                }
                changed["ref"]["contentHash"] = content_hash
                changed["serializedArtifactHash"] = hash_hex(
                    changed["artifact"]
                )
                self.assertFalse(
                    verify_result(
                        changed, self.recipes, self.result_context
                    )
                )

    def test_aggregate_authority_and_committed_result_set_fail_closed(self):
        case = next(
            item for item in self.cases
            if item["name"] == "vet-oneof-error-over-fail"
        )
        evaluation = case["evaluations"]["result"]
        self.assertEqual(case["expectedOutput"], execute_once(evaluation, self.document))
        for mutate in (
            lambda value: value["authority"].update(
                authenticatedSessionStart="not-trusted"
            ),
            lambda value: value["authority"]["vetInput"].update(
                recipeRegistryVersion=2
            ),
            lambda value: value["authority"]["vetInput"].update(
                sessionContext=None
            ),
            lambda value: value["resolvedResults"].pop(),
        ):
            changed = json.loads(json.dumps(evaluation))
            mutate(changed["input"])
            self.assertEqual(
                {
                    "decision": "error",
                    "reasons": ["aggregation authority invalid"],
                },
                execute_once(changed, self.document),
            )

    def test_nonce_ledger_is_verifier_owned_consumed_on_attempt_and_reused_by_capability(self):
        case = next(
            item for item in self.cases
            if item["name"] == "dacs1-cci-lei-named-matches"
        )
        value = case["evaluations"]["result"]["input"]
        runtime = VetReferenceRuntime(self.document["trustedContext"])
        invocation_id = value["authority"]["invocation"]
        challenge_id = runtime.invocations[invocation_id]["challengeId"]
        self.assertNotIn("consumed", value["authority"])
        admission = runtime.admit(value["authority"], value["bundle"])
        self.assertIsNotNone(admission)
        self.assertTrue(runtime.nonce_ledger.consumed(challenge_id))
        # Nested bundle checks consume only the capability, never the ledger.
        self.assertTrue(verify_bundle(value["bundle"], admission))
        self.assertTrue(verify_bundle(value["bundle"], admission))

        execution_runtime = VetReferenceRuntime(self.document["trustedContext"])
        self.assertTrue(execute(
            case["evaluations"]["result"], self.document, execution_runtime
        ))
        self.assertFalse(execute(
            case["evaluations"]["result"], self.document, execution_runtime
        ))

        for mutation in ("missing", "wrong"):
            with self.subTest(mutation=mutation):
                candidate = copy.deepcopy(value["bundle"])
                if mutation == "missing":
                    candidate.pop("sessionNonce")
                else:
                    candidate["sessionNonce"] = "00" * 16
                fresh_runtime = VetReferenceRuntime(self.document["trustedContext"])
                self.assertIsNone(fresh_runtime.admit(value["authority"], candidate))
                self.assertFalse(fresh_runtime.nonce_ledger.consumed(challenge_id))

        malformed = copy.deepcopy(value["bundle"])
        malformed["presentedBy"] = "key:" + "00" * 32
        fresh_runtime = VetReferenceRuntime(self.document["trustedContext"])
        self.assertIsNone(fresh_runtime.admit(value["authority"], malformed))
        self.assertTrue(
            fresh_runtime.nonce_ledger.consumed(challenge_id),
            "the exact issued nonce is consumed before later bundle binding fails",
        )

    def test_invocation_context_authenticates_phase_actor_and_authorities(self):
        case = next(
            item for item in self.cases
            if item["name"] == "dacs1-cci-lei-named-matches"
        )
        evaluation = case["evaluations"]["result"]
        self.assertTrue(execute_once(evaluation, self.document))
        invocation_id = evaluation["input"]["authority"]["invocation"]
        mutations = (
            lambda context: context.update(sessionState="completed"),
            lambda context: context.update(actor="seller"),
            lambda context: context.update(phaseIndex=True),
            lambda context: context.update(primaryClaim="key:" + "00" * 32),
            lambda context: context.update(expectedVerifier=context["phaseOrchestrator"]),
            lambda context: context.update(expectedVerifierRole=[]),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                document = copy.deepcopy(self.document)
                mutate(document["trustedContext"]["vetInvocations"][invocation_id])
                self.assertFalse(execute_once(evaluation, document))

        delegated = copy.deepcopy(self.document)
        delegated_context = delegated["trustedContext"]["vetInvocations"][invocation_id]
        delegated_context["expectedVerifierRole"] = "orchestrator"
        delegated_context["expectedVerifier"] = delegated_context["phaseOrchestrator"]
        issuance = next(
            item for item in delegated["trustedContext"]["nonceIssuances"]
            if item["challengeId"] == delegated_context["challengeId"]
        )
        issuance["expectedVerifier"] = delegated_context["phaseOrchestrator"]
        issuance["issuedBy"] = delegated_context["phaseOrchestrator"]
        self.assertTrue(execute_once(evaluation, delegated))

        shared_roles = copy.deepcopy(self.document)
        shared_context = shared_roles["trustedContext"]["vetInvocations"][invocation_id]
        shared_context["phaseOrchestrator"] = shared_context["expectedVerifier"]
        shared_context["anchorWriter"] = shared_context["expectedVerifier"]
        self.assertTrue(execute_once(evaluation, shared_roles))

        caller_snapshot = copy.deepcopy(evaluation)
        caller_snapshot["input"]["authority"]["consumed"] = False
        self.assertFalse(execute_once(caller_snapshot, self.document))

    def test_aggregate_receipt_logical_native_writer_and_time_are_authoritative(self):
        case = next(
            item for item in self.cases
            if item["name"] == "vet-oneof-error-over-fail"
        )
        evaluation = case["evaluations"]["result"]
        self.assertEqual(case["expectedOutput"], execute_once(evaluation, self.document))
        invocation_id = evaluation["input"]["authority"]["invocation"]
        invocation = self.document["trustedContext"]["vetInvocations"][invocation_id]
        receipt_id = invocation["recordReceiptId"]
        record = evaluation["input"]["record"]
        record_ref = evaluation["input"]["recordRef"]
        self.assertEqual(
            invocation["recordAnchorBinding"]["logicalAddress"],
            composite_logical_address(record["jobId"], record["evaluatedParty"]),
        )
        self.assertEqual(
            invocation["recordAnchorBinding"]["nativeAddress"],
            record_ref["anchor"]["locator"],
        )
        self.assertNotEqual(
            invocation["recordAnchorBinding"]["logicalAddress"],
            record_ref["anchor"]["locator"],
        )
        mutations = (
            lambda document, context, receipt: receipt.update(
                logicalAddress=receipt["nativeAddress"]
            ),
            lambda document, context, receipt: receipt.update(
                writer=context["expectedVerifier"]
            ),
            lambda document, context, receipt: receipt.update(state="submitted"),
            lambda document, context, receipt: receipt["blockRef"].update(
                timestamp=record["generatedAt"] - 1
            ),
            lambda document, context, receipt: context["recordAnchorBinding"].update(
                nativeAddress=context["recordAnchorBinding"]["logicalAddress"]
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                document = copy.deepcopy(self.document)
                context = document["trustedContext"]["vetInvocations"][invocation_id]
                receipt = document["trustedContext"]["authenticatedRecordReceipts"][receipt_id]
                mutate(document, context, receipt)
                self.assertEqual(
                    {"decision": "error", "reasons": ["aggregation authority invalid"]},
                    execute_once(evaluation, document),
                )

    def test_signed_generated_at_not_unsigned_wrapper_is_decision_time(self):
        case = next(
            item for item in self.cases
            if item["name"] == "vet-oneof-indeterminate-over-fail"
        )
        evaluation = case["evaluations"]["result"]
        changed = copy.deepcopy(evaluation)
        changed["input"]["evaluatedAt"] = SAFE_INT + 1
        self.assertEqual(case["expectedOutput"], execute_once(changed, self.document))

        invocation_id = evaluation["input"]["authority"]["invocation"]
        runtime = VetReferenceRuntime(self.document["trustedContext"])
        admission = runtime.admit(
            evaluation["input"]["authority"],
            evaluation["input"]["authority"]["vetInput"]["bundleToVet"],
        )
        projection = authenticate_production_aggregate(
            evaluation["input"],
            self.document["trustedContext"],
            self.recipes,
            self.result_context,
            admission,
            runtime,
        )
        self.assertEqual(
            evaluation["input"]["record"]["generatedAt"],
            projection["decisionTime"],
        )
        self.assertEqual(
            invocation_id,
            admission.invocation_id,
        )

        chronological = copy.deepcopy(evaluation)
        result_times = [
            item["artifact"]["verifiedAt"]
            for item in chronological["input"]["resolvedResults"]
        ]
        chronological["input"]["record"]["generatedAt"] = min(result_times) - 1
        chronological["input"] = resign_composite_input(chronological["input"])
        new_hash = chronological["input"]["recordRef"]["contentHash"]
        new_native = "stor-" + new_hash
        chronological["input"]["recordRef"]["anchor"]["locator"] = new_native
        document = copy.deepcopy(self.document)
        context = document["trustedContext"]["vetInvocations"][invocation_id]
        context["recordAnchorBinding"]["nativeAddress"] = new_native
        receipt = document["trustedContext"]["authenticatedRecordReceipts"][
            context["recordReceiptId"]
        ]
        receipt["nativeAddress"] = new_native
        receipt["contentHash"] = new_hash
        self.assertEqual(
            {"decision": "error", "reasons": ["aggregation authority invalid"]},
            execute_once(chronological, document),
        )

    def test_jcs_and_claim_reference_boundaries_are_shared_and_fail_closed(self):
        self.assertTrue(canonical_equal(1, 1.0))
        demos = "did:demos:agent:" + "11" * 32
        self.assertEqual(parse_ref(demos), ("did", demos.split(":", 1)[1]))
        for escaped in ("did:example:subject%3Aretained", "did:example:subject%3aretained"):
            self.assertEqual(parse_ref(escaped), ("did", escaped[4:]))
        for reference in (
            "did:example:subject%A",
            "did:example:subject%3g",
            "did:example:subject:",
            "did:demos:agent:" + "AA" * 32,
        ):
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                parse_ref(reference)

        case = next(
            item for item in self.cases
            if item["name"]
            == "vet-control-existence-only-lei-supporting-context"
        )
        for invalid in (float("nan"), float("inf"), SAFE_INT + 1, "\ud800"):
            with self.subTest(invalid=repr(invalid)):
                changed = copy.deepcopy(case["evaluations"]["result"])
                changed["input"]["requirement"]["required"][0]["parameters"] = {
                    "required": invalid
                }
                self.assertEqual("error", execute_once(changed, self.document))

    def test_registered_reference_component_shapes(self):
        valid = (
            "cci-xm:evm:mainnet:0x1234", "cci-web2:github:example",
            "cci-pqc:falcon:issued-key", "stor-cred:certificate:issued-id",
            "substrate-validator-set:demos:epoch-1", "sam-uei:ABC123DEF456",
            "naics:541511", "erc8004:1:0x" + "ab" * 20 + ":0",
        )
        for value in valid:
            with self.subTest(value=value):
                self.assertEqual(parse_claim_reference(value).canonical, value)
        for value in (
            "cci-xm:evm:mainnet:", "cci-web2:github:", "cci-pqc:falcon",
            "stor-cred:certificate", "substrate-validator-set:demos:",
            "sam-uei:ABC", "naics:12345", "cci-lei:" + "A" * 20,
            "erc8004:01:0x" + "ab" * 20 + ":0",
            "erc8004:1:0x" + "ab" * 20 + ":" + str(2**256),
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_claim_reference(value)

    def test_every_invocation_binds_authenticated_session_and_recipe_pin(self):
        for name in self.document["trustedContext"]["vetInvocations"]:
            for source, field, value in (
                ("invocation", "recipeRegistryVersion", 2),
                ("session", "recipeRegistryVersion", 2),
                ("session", "jobId", "01J00000000000000000000999"),
                ("registry", "recipeRegistryVersion", 2),
            ):
                with self.subTest(invocation=name, source=source, field=field):
                    context = copy.deepcopy(self.document["trustedContext"])
                    invocation = context["vetInvocations"][name]
                    target = {
                        "invocation": invocation,
                        "session": context["authenticatedSessionStarts"][invocation["sessionStart"]],
                        "registry": context["recipeRegistry"],
                    }[source]
                    target[field] = value
                    self.assertIsNone(VetReferenceRuntime(context)._trusted_invocation(name))

    def test_verify_results_remain_session_agnostic_reusable_v1_artifacts(self):
        artifacts = [
            result["artifact"]
            for case in self.cases
            for evaluation in case["evaluations"].values()
            for result in evaluation["input"]["resolvedResults"]
        ]
        self.assertTrue(artifacts)
        for artifact in artifacts:
            with self.subTest(reference=(artifact["scheme"], artifact["identifier"])):
                self.assertFalse(
                    {"jobId", "sessionNonce", "attempt", "challenge"} & set(artifact)
                )
        aggregate = next(
            item for item in self.cases if item["name"] == "vet-oneof-error-over-fail"
        )["evaluations"]["result"]["input"]
        invocation = self.document["trustedContext"]["vetInvocations"][
            aggregate["authority"]["invocation"]
        ]
        self.assertNotEqual(
            aggregate["record"]["signature"]["signer"], AUTHORITY_REF
        )
        self.assertNotEqual(invocation["anchorWriter"], AUTHORITY_REF)
        self.assertNotEqual(
            invocation["anchorWriter"], aggregate["record"]["signature"]["signer"]
        )

    def test_supplementary_signals_are_signed_but_not_result_references(self):
        case = next(
            item for item in self.cases
            if item["name"] == "vet-oneof-error-over-fail"
        )
        evaluation = case["evaluations"]["result"]
        record = evaluation["input"]["record"]
        self.assertTrue(record["supplementary"])
        resolved_refs = [
            canonical_bytes(item["ref"])
            for item in evaluation["input"]["resolvedResults"]
        ]
        committed_refs = [
            canonical_bytes(item)
            for item in record["freshness"] + record["dealSpecific"]
        ]
        self.assertEqual(committed_refs, resolved_refs)
        self.assertTrue(all(
            not isinstance(signal, dict)
            or "anchor" not in signal
            for signal in record["supplementary"]
        ))
        self.assertEqual(
            case["expectedOutput"], execute_once(evaluation, self.document)
        )

        changed = copy.deepcopy(evaluation["input"])
        changed["record"]["supplementary"][0]["observedAt"] = -1
        changed = resign_composite_input(changed)
        self.assertEqual(
            {"decision": "error", "reasons": ["aggregation authority invalid"]},
            aggregate_output(
                changed,
                self.document["trustedContext"],
                self.recipes,
                self.result_context,
                VetReferenceRuntime(self.document["trustedContext"]),
            ),
        )

    def test_malformed_and_duplicate_resolved_entries_fail_without_throwing(self):
        case = next(
            item for item in self.cases
            if item["name"]
            == "vet-control-existence-only-lei-supporting-context"
        )
        evaluation = case["evaluations"]["result"]
        mutations = ([None], [{}], [
            copy.deepcopy(evaluation["input"]["resolvedResults"][0]),
            copy.deepcopy(evaluation["input"]["resolvedResults"][0]),
        ])
        for resolved in mutations:
            with self.subTest(resolved=resolved):
                changed = copy.deepcopy(evaluation)
                changed["input"]["resolvedResults"] = resolved
                self.assertEqual("error", execute_once(changed, self.document))

        malformed_anchor = copy.deepcopy(evaluation)
        malformed_anchor["input"]["resolvedResults"][0]["ref"]["anchor"] = {
            "kind": [], "locator": "x"
        }
        self.assertEqual("error", execute_once(malformed_anchor, self.document))
        self.assertFalse(
            well_formed_attestation_ref({
                "anchor": {"kind": [], "locator": "x"},
                "contentHash": "00" * 32,
                "signer": AUTHORITY_REF,
            })
        )

        aggregate = next(
            item for item in self.cases
            if item["name"] == "vet-oneof-error-over-fail"
        )["evaluations"]["result"]
        malformed_record_anchor = copy.deepcopy(aggregate)
        malformed_record_anchor["input"]["recordRef"]["anchor"] = []
        self.assertEqual(
            {"decision": "error", "reasons": ["aggregation authority invalid"]},
            execute_once(malformed_record_anchor, self.document),
        )

    def test_container_fields_reject_at_shared_vet_helpers(self):
        evaluation = next(
            item for item in self.cases
            if item["name"] == "vet-control-existence-only-lei-supporting-context"
        )["evaluations"]["result"]
        value = evaluation["input"]
        runtime = VetReferenceRuntime(self.document["trustedContext"])
        admission = runtime.admit(value["authority"], value["bundle"])
        self.assertIsNotNone(admission)
        self.assertTrue(verify_bundle(value["bundle"], admission))
        self.assertTrue(valid_requirement(value["requirement"]))
        self.assertTrue(verify_result(
            value["resolvedResults"][0], self.recipes, self.result_context
        ))
        numeric_equivalent = copy.deepcopy(value["resolvedResults"][0])
        numeric_equivalent["artifact"]["recipeVersion"] = float(
            numeric_equivalent["artifact"]["recipeVersion"]
        )
        self.assertTrue(verify_result(
            numeric_equivalent, self.recipes, self.result_context
        ))

        for malformed in (None, [], {}):
            with self.subTest(malformed=malformed):
                bundle = copy.deepcopy(value["bundle"])
                bundle["presentation"]["signatures"][0]["ref"] = malformed
                self.assertFalse(verify_bundle(bundle, admission))

                requirement = copy.deepcopy(value["requirement"])
                requirement["required"][0]["scheme"] = malformed
                self.assertFalse(valid_requirement(requirement))
                self.assertEqual(
                    ("error", ["invalid bundle requirement"]),
                    evaluate(
                        {**value, "requirement": requirement},
                        self.recipes, self.result_context,
                        decision_time=admission.trusted_now, admission=admission,
                    ),
                )
                ordinary = copy.deepcopy(evaluation)
                ordinary["input"]["requirement"] = requirement
                self.assertEqual("error", execute_once(ordinary, self.document))

                grouped = copy.deepcopy(value["requirement"])
                grouped["oneOf"] = [[requirement["required"][0]]]
                self.assertFalse(valid_requirement(grouped))

                for field in ("scheme", "method", "recipeVersion"):
                    with self.subTest(field=field):
                        resolved = copy.deepcopy(value["resolvedResults"][0])
                        resolved["artifact"][field] = malformed
                        self.assertFalse(verify_result(
                            resolved, self.recipes, self.result_context
                        ))
                resolved = copy.deepcopy(value["resolvedResults"][0])
                resolved["artifact"]["signature"]["signer"] = malformed
                self.assertFalse(verify_result(
                    resolved, self.recipes, self.result_context
                ))

    def test_aggregate_session_names_reject_before_registry_lookup(self):
        case = next(
            item for item in self.cases
            if item["name"] == "vet-oneof-error-over-fail"
        )
        evaluation = case["evaluations"]["result"]
        self.assertEqual(case["expectedOutput"], execute_once(evaluation, self.document))
        for malformed in (None, [], {}):
            with self.subTest(malformed=malformed):
                changed = copy.deepcopy(evaluation["input"])
                changed["authority"]["authenticatedSessionStart"] = malformed
                runtime = VetReferenceRuntime(self.document["trustedContext"])
                admission = runtime.admit(
                    changed["authority"], changed["authority"]["vetInput"]["bundleToVet"]
                )
                self.assertIsNotNone(admission)
                self.assertIsNone(authenticate_production_aggregate(
                    changed, self.document["trustedContext"], self.recipes,
                    self.result_context, admission, runtime,
                ))
                self.assertEqual(
                    {"decision": "error", "reasons": ["aggregation authority invalid"]},
                    aggregate_output(
                        changed, self.document["trustedContext"], self.recipes,
                        self.result_context,
                        VetReferenceRuntime(self.document["trustedContext"]),
                    ),
                )

    def test_max_age_must_be_a_nonnegative_safe_integer(self):
        case = next(
            item for item in self.cases
            if item["name"]
            == "vet-control-existence-only-lei-supporting-context"
        )
        evaluation = case["evaluations"]["result"]
        for max_age in ("60", -1, SAFE_INT + 1, True):
            with self.subTest(max_age=max_age):
                changed = copy.deepcopy(evaluation)
                changed["input"]["requirement"]["required"][0][
                    "maxAge"
                ] = max_age
                self.assertEqual("error", execute_once(changed, self.document))

    def test_authenticated_result_context_is_complete_and_independent(self):
        self.assertIsNotNone(self.result_context)
        result_refs = {
            canonical_bytes(result["ref"])
            for case in self.cases
            for evaluation in case["evaluations"].values()
            for result in evaluation["input"]["resolvedResults"]
        }
        source_refs = {
            canonical_bytes(result["artifact"]["attestation"])
            for case in self.cases
            for evaluation in case["evaluations"].values()
            for result in evaluation["input"]["resolvedResults"]
        }
        self.assertEqual(
            result_refs, set(self.result_context["resultHashByRef"])
        )
        self.assertEqual(
            source_refs, set(self.result_context["attestationByKey"])
        )

    def test_valid_replacement_signer_cannot_preserve_result_authority(self):
        resolved = next(
            result
            for case in self.cases
            for evaluation in case["evaluations"].values()
            for result in evaluation["input"]["resolvedResults"]
        )
        attacker = fixture_private_key("replacement-signer")
        attacker_ref = public_ref(attacker)
        changed = resign_result(resolved, attacker, attacker_ref)
        self.assertEqual(
            resolved["ref"]["contentHash"], changed["ref"]["contentHash"]
        )
        self.assertFalse(
            verify_result(changed, self.recipes, self.result_context)
        )
        # Even granting the replacement its new full-artifact hash cannot make
        # its self-declared signing key an authenticated result authority.
        trust = copy.deepcopy(self.result_context)
        trust["resultHashByRef"][canonical_bytes(changed["ref"])] = changed[
            "serializedArtifactHash"
        ]
        self.assertFalse(verify_result(changed, self.recipes, trust))
        with mock.patch(f"{__name__}.verify_signature", return_value=True):
            self.assertFalse(verify_result(changed, self.recipes, trust))

    def test_noncanonical_identifiers_for_each_exercised_family_reject(self):
        invalid = [
            "key:0x" + "11" * 32,
            "lei:not-a-valid-lei",
            "cci-lei:984500abcdef12345678",
            "finra-crd:012345",
            "did:Example:subject",
            "domain:Example.com",
            "domain:127.0.0.1",
        ]
        for reference in invalid:
            with self.subTest(reference=reference):
                with self.assertRaises(ValueError):
                    parse_ref(reference)

    def test_bad_signature_and_wrong_domain_are_rejected_after_hash_binding(self):
        resolved = next(
            result
            for case in self.cases
            for evaluation in case["evaluations"].values()
            for result in evaluation["input"]["resolvedResults"]
        )
        bad = copy.deepcopy(resolved)
        signature_value = bad["artifact"]["signature"]["value"]
        bad["artifact"]["signature"]["value"] = (
            ("A" if signature_value[0] != "A" else "B")
            + signature_value[1:]
        )
        bad["serializedArtifactHash"] = hash_hex(bad["artifact"])
        bad_trust = copy.deepcopy(self.result_context)
        bad_trust["resultHashByRef"][canonical_bytes(bad["ref"])] = bad[
            "serializedArtifactHash"
        ]
        self.assertFalse(verify_result(bad, self.recipes, bad_trust))

        wrong_domain = resign_result(
            resolved,
            fixture_private_key("authority"),
            AUTHORITY_REF,
            domain="dacs-composite:v1:",
        )
        wrong_domain_trust = copy.deepcopy(self.result_context)
        wrong_domain_trust["resultHashByRef"][
            canonical_bytes(wrong_domain["ref"])
        ] = wrong_domain["serializedArtifactHash"]
        self.assertFalse(
            verify_result(wrong_domain, self.recipes, wrong_domain_trust)
        )

    def test_malformed_ref_source_substitution_and_missing_family_reject(self):
        resolved = next(
            result
            for case in self.cases
            for evaluation in case["evaluations"].values()
            for result in evaluation["input"]["resolvedResults"]
        )
        malformed = copy.deepcopy(resolved)
        malformed["ref"]["contentHash"] = "not-a-hash"
        self.assertFalse(
            verify_result(malformed, self.recipes, self.result_context)
        )

        authority = fixture_private_key("authority")
        source_swap = copy.deepcopy(resolved)
        source_swap["artifact"]["attestation"]["contentHash"] = "00" * 32
        source_swap = resign_result(source_swap, authority, AUTHORITY_REF)
        source_trust = copy.deepcopy(self.result_context)
        source_trust["resultHashByRef"][
            canonical_bytes(source_swap["ref"])
        ] = source_swap["serializedArtifactHash"]
        self.assertFalse(
            verify_result(source_swap, self.recipes, source_trust)
        )

        family_swap = copy.deepcopy(resolved)
        family_swap["artifact"]["method"] = "oauth-attested"
        family_swap = resign_result(family_swap, authority, AUTHORITY_REF)
        family_trust = copy.deepcopy(self.result_context)
        family_trust["resultHashByRef"][
            canonical_bytes(family_swap["ref"])
        ] = family_swap["serializedArtifactHash"]
        self.assertFalse(
            verify_result(family_swap, self.recipes, family_trust)
        )

    def test_duplicate_result_refs_fail_before_lookup(self):
        case = next(
            item for item in self.cases
            if item["name"] == "dacs1-cci-lei-named-matches"
        )
        changed = copy.deepcopy(case["evaluations"]["result"])
        changed["input"]["resolvedResults"].append(
            copy.deepcopy(changed["input"]["resolvedResults"][0])
        )
        self.assertFalse(execute_once(changed, self.document))

    def test_signed_noncanonical_lei_cannot_satisfy_presence(self):
        case = next(
            item for item in self.cases
            if item["name"]
            == "vet-control-existence-only-lei-supporting-context"
        )
        original = case["evaluations"]["result"]["input"]["bundle"]
        bundle = copy.deepcopy(original)
        lei_claim = next(
            item for item in bundle["claims"] if item["ref"].startswith("lei:")
        )
        lei_claim["ref"] = "lei:not-a-valid-lei"
        lei_claim.pop("verifiedBy", None)
        bundle = resign_bundle(
            bundle,
            fixture_private_key("presenter"),
            public_ref(fixture_private_key("presenter")),
        )
        evaluation = {
            "operation": "match",
            "input": {
                "evaluatedAt": 1_900_000_000_000,
                "bundle": bundle,
                "authority": copy.deepcopy(
                    case["evaluations"]["result"]["input"]["authority"]
                ),
                "requirement": {
                    "requirementVersion": "1",
                    "required": [{
                        "scheme": "lei", "verificationRequired": False,
                    }],
                },
                "resolvedResults": [],
            },
        }
        self.assertFalse(execute_once(evaluation, self.document))

    def test_resigned_method_and_data_substitution_cannot_flip_control(self):
        case = next(
            item for item in self.cases
            if item["name"]
            == "vet-control-existence-method-forged-holderbinding-reject"
        )
        changed = copy.deepcopy(case["evaluations"]["result"])
        old_result = changed["input"]["resolvedResults"][0]
        old_ref = old_result["ref"]
        old_result["artifact"]["method"] = "verifiable-credential"
        old_result["artifact"]["data"] = {
            "holderBinding": {
                "controller": public_ref(fixture_private_key("presenter")),
            },
        }
        new_result = resign_result(
            old_result,
            fixture_private_key("authority"),
            AUTHORITY_REF,
        )
        changed["input"]["resolvedResults"][0] = new_result
        bundle = changed["input"]["bundle"]
        for claim in bundle["claims"]:
            if claim.get("verifiedBy") == old_ref:
                claim["verifiedBy"] = copy.deepcopy(new_result["ref"])
        changed["input"]["bundle"] = resign_bundle(
            bundle,
            fixture_private_key("presenter"),
            public_ref(fixture_private_key("presenter")),
        )
        self.assertNotEqual("pass", execute_once(changed, self.document))

    def test_vpc4_terminal_fault_attribution_is_derived(self):
        self.assertEqual("counterparty", vpc4_error_class("fail"))
        self.assertEqual("permanent", vpc4_error_class("error"))
        self.assertEqual("permanent", vpc4_error_class("indeterminate"))
        self.assertEqual(
            "counterparty",
            vpc4_error_class("error", counterparty_malformed=True),
        )
        self.assertNotEqual("transient", vpc4_error_class("error"))


if __name__ == "__main__":
    unittest.main()
