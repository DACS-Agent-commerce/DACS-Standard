import base64
import copy
import hashlib
import importlib.util
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
    REGISTERED_SCHEMES,
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
from raw_json_profile import RawJsonProfileError, loads as load_raw_json  # noqa: E402

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
KNOWN_SCHEMES = set(REGISTERED_SCHEMES)
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
VC_ISSUER_REF = "did:example:dacs-vc-issuer"
VALIDATOR_SET_REF = "substrate-validator-set:fixture:validators"


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


def parse_ref(value, registered_schemes=None):
    parsed = parse_claim_reference(
        value,
        registered_schemes=(
            KNOWN_SCHEMES if registered_schemes is None else registered_schemes
        ),
    )
    return parsed.identity


# CORE CF-5(5): container depth 128 is admitted and 129 is rejected; a
# top-level object or array has depth 1.
MAX_JSON_DEPTH = 128


def within_json_depth(value, limit=MAX_JSON_DEPTH):
    """Iterative CF-5(5) depth check that cannot hit a host recursion limit."""

    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, (dict, list)):
            depth += 1
            if depth > limit:
                return False
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, depth) for child in children)
    return True


def integral_numbers(value):
    """CORE CF-5(4): JSON spellings of one admitted binary64 value are one value.

    ``1900000060000.0`` and ``1.90000006e12`` have the same JCS bytes as
    ``1900000060000``, so the host parser's int/float split must not change a
    verdict.  Returns a copy with integral safe-range floats as ints; fractional
    numbers are untouched.  The walk is iterative, copies each shared container
    once, and refuses a cyclic in-process value, which no JSON text can express.
    """

    copies = {}
    active = set()
    root = [value]
    stack = [(root, 0, None)]
    while stack:
        container, key, leaving = stack.pop()
        if leaving is not None:
            active.discard(leaving)
            continue
        item = container[key]
        if isinstance(item, float):
            if math.isfinite(item) and item.is_integer() and abs(item) <= SAFE_INT:
                container[key] = int(item)
        elif isinstance(item, (dict, list)):
            ident = id(item)
            if ident in active:
                raise ValueError("cyclic value is not JSON")
            if ident in copies:
                container[key] = copies[ident]
                continue
            clone = dict(item) if isinstance(item, dict) else list(item)
            copies[ident] = container[key] = clone
            active.add(ident)
            stack.append((None, None, ident))
            names = list(clone) if isinstance(clone, dict) else range(len(clone))
            stack.extend((clone, name, None) for name in names)
    return root[0]


def all_safe_integers(value):
    if not within_json_depth(value):
        return False
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, bool):
            continue
        if isinstance(item, int):
            if not -SAFE_INT <= item <= SAFE_INT:
                return False
        elif isinstance(item, float):
            if not math.isfinite(item) or not -SAFE_INT <= item <= SAFE_INT:
                return False
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
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


def resign_composite_input(value, *, signer_name="verifier"):
    changed = copy.deepcopy(value)
    record = changed["record"]
    unsigned = {
        name: item for name, item in record.items() if name != "signature"
    }
    record_hash = hash_hex(unsigned)
    verifier = fixture_private_key(signer_name)
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


def reanchor_composite_input(value, document, *, signer_name="verifier"):
    """Re-sign ``value["record"]`` and move the trusted receipt to its bytes.

    Mutations that change signed record bytes must not be rejected merely by
    the old receipt content hash, or the targeted guard would go untested.
    """

    changed = resign_composite_input(value, signer_name=signer_name)
    content_hash = changed["recordRef"]["contentHash"]
    native = "stor-" + content_hash
    changed["recordRef"]["anchor"]["locator"] = native
    context = document["trustedContext"]["vetInvocations"][
        changed["authority"]["invocation"]
    ]
    context["recordAnchorBinding"]["nativeAddress"] = native
    receipt = document["trustedContext"]["authenticatedRecordReceipts"][
        context["recordReceiptId"]
    ]
    receipt["nativeAddress"] = native
    receipt["contentHash"] = content_hash
    return changed


def rebuild_direct_result(evaluation, document, mutate_artifact, *, index=0):
    """Re-sign one resolved result with the genuine result authority.

    The replacement is registered as an authenticated artifact and the bundle
    claim is re-pointed and re-signed, so only the mutated field can decide.
    """

    changed = copy.deepcopy(evaluation)
    resolved = changed["input"]["resolvedResults"][index]
    old_ref = copy.deepcopy(resolved["ref"])
    mutate_artifact(resolved["artifact"])
    replacement = resign_result(
        resolved, fixture_private_key("authority"), AUTHORITY_REF
    )
    changed["input"]["resolvedResults"][index] = replacement
    artifacts = document["trustedContext"]["authenticatedResultArtifacts"]
    if all(
        canonical_bytes(item["ref"]) != canonical_bytes(replacement["ref"])
        for item in artifacts
    ):
        artifacts.append({
            "ref": copy.deepcopy(replacement["ref"]),
            "serializedArtifactHash": replacement["serializedArtifactHash"],
        })
    provenance = document["trustedContext"]["authenticatedResultProvenance"]
    invocation = changed["input"]["authority"]["invocation"]
    requirement = changed["input"]["requirement"]
    artifact = replacement["artifact"]
    member = next(
        item
        for item in [
            *requirement.get("required", []),
            *(m for group in requirement.get("oneOf", []) for m in group),
        ]
        if item.get("scheme") == artifact.get("scheme")
    )
    provenance_entry = {
        "ref": copy.deepcopy(replacement["ref"]),
        "serializedArtifactHash": replacement["serializedArtifactHash"],
        "currentProductions": [{
            "invocation": invocation,
            "requirementHash": hash_hex(requirement),
            "memberHash": hash_hex(member),
        }],
        "cachedOrigins": [],
    }
    existing = next((
        item for item in provenance
        if canonical_bytes(item["ref"]) == canonical_bytes(replacement["ref"])
        and item["serializedArtifactHash"] == replacement["serializedArtifactHash"]
    ), None)
    if existing is None:
        provenance.append(provenance_entry)
    else:
        production = provenance_entry["currentProductions"][0]
        if production not in existing["currentProductions"]:
            existing["currentProductions"].append(production)
    bundle = changed["input"]["bundle"]
    for claim in bundle["claims"]:
        if claim.get("verifiedBy") == old_ref:
            claim["verifiedBy"] = copy.deepcopy(replacement["ref"])
    presenter = fixture_private_key("presenter")
    changed["input"]["bundle"] = resign_bundle(
        bundle, presenter, public_ref(presenter)
    )
    return changed


def result_provenance_entry(document, resolved):
    key = canonical_bytes(resolved["ref"])
    artifact_hash = resolved["serializedArtifactHash"]
    return next(
        item
        for item in document["trustedContext"]["authenticatedResultProvenance"]
        if canonical_bytes(item["ref"]) == key
        and item["serializedArtifactHash"] == artifact_hash
    )


def set_result_provenance(document, resolved, *, current=(), cached=()):
    entry = result_provenance_entry(document, resolved)
    entry["currentProductions"] = copy.deepcopy(list(current))
    entry["cachedOrigins"] = copy.deepcopy(list(cached))


def rebuild_aggregate_result(
    evaluation, document, mutate_artifact, *, index, overall_decision
):
    """Re-sign and commit one verifier-produced aggregate result replacement."""

    changed = copy.deepcopy(evaluation)
    value = changed["input"]
    old = value["resolvedResults"][index]
    replacement_source = copy.deepcopy(old)
    mutate_artifact(replacement_source["artifact"])
    replacement = resign_result(
        replacement_source, fixture_private_key("authority"), AUTHORITY_REF
    )
    value["resolvedResults"][index] = replacement
    document["trustedContext"]["authenticatedResultArtifacts"].append({
        "ref": copy.deepcopy(replacement["ref"]),
        "serializedArtifactHash": replacement["serializedArtifactHash"],
    })
    requirement = value["authority"]["vetInput"]["requirement"]
    member = next(
        item
        for item in [
            *requirement.get("required", []),
            *(member for group in requirement.get("oneOf", []) for member in group),
        ]
        if item.get("scheme") == replacement["artifact"].get("scheme")
    )
    document["trustedContext"]["authenticatedResultProvenance"].append({
        "ref": copy.deepcopy(replacement["ref"]),
        "serializedArtifactHash": replacement["serializedArtifactHash"],
        "currentProductions": [{
            "invocation": value["authority"]["invocation"],
            "requirementHash": hash_hex(requirement),
            "memberHash": hash_hex(member),
        }],
        "cachedOrigins": [],
    })
    value["record"]["dealSpecific"] = [
        copy.deepcopy(replacement["ref"])
        if canonical_bytes(ref) == canonical_bytes(old["ref"])
        else ref
        for ref in value["record"]["dealSpecific"]
    ]
    value["record"]["requirementHash"] = hash_hex(requirement)
    value["record"]["overallDecision"] = overall_decision
    changed["input"] = reanchor_composite_input(value, document)
    return changed


def set_result_attestation_family(document, resolved):
    artifact = resolved["artifact"]
    entry = next(
        item
        for item in document["trustedContext"]["authenticatedSourceAttestations"]
        if canonical_bytes(item["attestation"])
        == canonical_bytes(artifact["attestation"])
    )
    entry.update(
        scheme=artifact["scheme"],
        method=artifact["method"],
        recipeVersion=artifact["recipeVersion"],
    )


def resign_recipe(recipe):
    unsigned = {key: value for key, value in recipe.items() if key != "signature"}
    recipe["signature"] = {
        "algorithm": "ed25519",
        "signer": RECIPE_STEWARD_REF,
        "value": b64url_encode(
            fixture_private_key("recipe-steward").sign(
                (RECIPE_DOMAIN + hash_hex(unsigned)).encode("ascii")
            )
        ),
    }


def safe_number(value):
    """Return whether one field is a CORE numeric safe-magnitude value."""

    return (
        type(value) in (int, float)
        and -SAFE_INT <= value <= SAFE_INT
        and (type(value) is int or math.isfinite(value))
    )


def canonical_claim_reference(value):
    try:
        parsed = parse_claim_reference(value)
    except (TypeError, ValueError):
        return False
    return parsed.canonical == value


def verification_method_valid(method):
    """Validate one signed DACS-2 VerificationMethod union member.

    Unknown members remain in the signed object and its signature hash (SIG-5),
    but only the defined members below can affect method resolution or authority.
    """

    if not isinstance(method, dict):
        return False
    kind = method.get("kind")
    if not isinstance(kind, str) or kind not in KNOWN_METHODS:
        return False
    if kind == "verifiable-credential":
        issuers = method.get("issuerAllowList")
        return (
            (
                "issuerAllowList" not in method
                or (
                    isinstance(issuers, list)
                    and all(canonical_claim_reference(item) for item in issuers)
                )
            )
            and (
                "schemaUrl" not in method
                or isinstance(method["schemaUrl"], str)
            )
        )
    if kind == "tlsnotary":
        return isinstance(method.get("endpoint"), str) and (
            "sessionTemplate" not in method
            or isinstance(method["sessionTemplate"], str)
        )
    if kind == "zktls":
        return isinstance(method.get("provider"), str) and isinstance(
            method.get("programId"), str
        )
    if kind == "consensus-backed-proxy":
        endpoint = method.get("endpoint")
        if (
            not isinstance(endpoint, dict)
            or not isinstance(endpoint.get("method"), str)
            or endpoint["method"] not in {"GET", "POST"}
            or not isinstance(endpoint.get("urlTemplate"), str)
            or (
                "headers" in endpoint
                and (
                    not isinstance(endpoint["headers"], dict)
                    or any(
                        not isinstance(name, str) or not isinstance(value, str)
                        for name, value in endpoint["headers"].items()
                    )
                )
            )
            or (
                "body" in endpoint
                and not isinstance(endpoint["body"], str)
            )
        ):
            return False
        return True
    if kind == "oauth-attested":
        scopes = method.get("scopes")
        return (
            isinstance(method.get("provider"), str)
            and isinstance(scopes, list)
            and all(isinstance(scope, str) for scope in scopes)
            and safe_number(method.get("maxTokenAgeSec"))
        )
    if kind == "evm-rpc":
        return (
            safe_number(method.get("chainId"))
            and isinstance(method.get("contract"), str)
            and isinstance(method.get("method"), str)
            and ("args" not in method or isinstance(method["args"], list))
        )
    if kind == "domain-tls-control":
        challenge_type = method.get("challengeType")
        return isinstance(challenge_type, str) and challenge_type in {
            "http-01", "dns-01", "tls-alpn-01"
        }
    # self-signed and demos-gcr-domain have no variant-specific fields.
    return True


def recipe_methods(recipe):
    default = recipe.get("defaultMethod")
    alternatives = recipe.get("alternatives", [])
    if (
        not isinstance(default, dict)
        or not isinstance(alternatives, list)
        or any(not isinstance(item, dict) for item in alternatives)
    ):
        return None
    methods = [default, *alternatives]
    kinds = [item.get("kind") for item in methods]
    if (
        any(not verification_method_valid(item) for item in methods)
        or len(kinds) != len(set(kinds))
    ):
        return None
    return methods


def append_recipe_authorities(context, recipe):
    """Register every signed execution tuple supported by one recipe."""

    for method in recipe_methods(recipe):
        context["resultAuthorities"].append({
            "scheme": recipe["scheme"],
            "method": method["kind"],
            "recipeVersion": recipe["recipeVersion"],
            "algorithm": "ed25519",
            "signer": AUTHORITY_REF,
        })


def owning_recipe_family(recipes, scheme, selected_method):
    """Return the unique signed default-method owner before eligibility."""

    if not isinstance(recipes, dict) or selected_method not in KNOWN_METHODS:
        return None
    owners = {
        owner
        for (candidate_scheme, owner, _), recipe in recipes.items()
        if candidate_scheme == scheme
        and any(
            method.get("kind") == selected_method
            for method in (recipe_methods(recipe) or [])
        )
    }
    return next(iter(owners)) if len(owners) == 1 else None


def recipe_for_method_version(recipes, scheme, selected_method, version):
    owner = owning_recipe_family(recipes, scheme, selected_method)
    recipe = recipes.get((scheme, owner, version)) if owner is not None else None
    if recipe is None or not any(
        method.get("kind") == selected_method
        for method in (recipe_methods(recipe) or [])
    ):
        return None
    return recipe


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
        methods = recipe_methods(recipe)
        method = recipe.get("defaultMethod")
        if (
            not isinstance(signature, dict)
            or set(signature) != {"algorithm", "signer", "value"}
            or signature.get("algorithm") != "ed25519"
            or signature.get("signer") != RECIPE_STEWARD_REF
            or methods is None
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
            or type(version) is not int
            or version < 1
            or not exact_safe_integer(recipe.get("defaultMaxAgeSec"), minimum=0)
            or recipe.get("availability") not in RECIPE_AVAILABILITIES
            or recipe.get("governance", {}).get("proposedBy")
            != RECIPE_STEWARD_REF
        ):
            return None
        has_parser = isinstance(recipe.get("parserRules"), dict)
        if any(item["kind"] in PARSER_METHODS for item in methods) != has_parser:
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
    ownership = {}
    for (scheme, owner, _), recipe in resolved.items():
        for method in recipe_methods(recipe):
            key = (scheme, method["kind"])
            prior = ownership.setdefault(key, owner)
            if prior != owner:
                return None
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
    if (
        not isinstance(value, dict)
        or not {"anchor", "contentHash"} <= set(value)
        or set(value) - {"anchor", "contentHash", "signer"}
    ):
        return False
    anchor = value.get("anchor")
    if "signer" in value:
        try:
            parse_ref(value["signer"])
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
    )


def authenticated_result_context(document, recipes):
    context = document.get("trustedContext")
    if not isinstance(context, dict) or not isinstance(recipes, dict):
        return None
    authorities = context.get("resultAuthorities")
    attestations = context.get("authenticatedSourceAttestations")
    result_artifacts = context.get("authenticatedResultArtifacts")
    result_provenance = context.get("authenticatedResultProvenance")
    invocations = context.get("vetInvocations")
    if not all(
        isinstance(items, list)
        for items in (
            authorities, attestations, result_artifacts, result_provenance
        )
    ) or not isinstance(invocations, dict):
        return None

    authority_by_family = {}
    for authority in authorities:
        if not isinstance(authority, dict) or set(authority) != {
            "scheme", "method", "recipeVersion", "algorithm", "signer"
        }:
            return None
        execution = (
            authority.get("scheme"),
            authority.get("method"),
            authority.get("recipeVersion"),
        )
        if (
            recipe_for_method_version(recipes, *execution) is None
            or authority.get("algorithm") != "ed25519"
            or authority.get("signer") != AUTHORITY_REF
            or execution in authority_by_family
        ):
            return None
        authority_by_family[execution] = authority
    expected_executions = {
        (scheme, method["kind"], version)
        for (scheme, _, version), recipe in recipes.items()
        for method in recipe_methods(recipe)
    }
    if set(authority_by_family) != expected_executions:
        return None

    attestation_by_key = {}
    for entry in attestations:
        required = {
            "attestation", "resolvedSourceHash", "scheme", "method",
            "recipeVersion", "resultSigner",
        }
        if (
            not isinstance(entry, dict)
            or not required <= set(entry)
            or set(entry) - required - {"sourceAuthority"}
        ):
            return None
        family = (
            entry.get("scheme"), entry.get("method"), entry.get("recipeVersion")
        )
        attestation = entry.get("attestation")
        source_authority = entry.get("sourceAuthority")
        source_identity = None
        if source_authority is not None:
            if (
                not isinstance(source_authority, dict)
                or set(source_authority) != {"kind", "claim"}
                or source_authority.get("kind") not in {
                    "issuer", "validator-set", "signer"
                }
            ):
                return None
            try:
                source_identity = parse_ref(source_authority.get("claim"))
            except ValueError:
                return None
        if not well_formed_attestation_ref(attestation):
            return None
        key = canonical_bytes(attestation)
        if (
            family not in authority_by_family
            or entry.get("resolvedSourceHash") != attestation["contentHash"]
            or entry.get("resultSigner")
            != authority_by_family[family]["signer"]
            or ("signer" in attestation) != (source_authority is not None)
            or (
                source_authority is not None
                and attestation["signer"] != source_authority["claim"]
            )
            or (
                entry.get("method") == "verifiable-credential"
                and (
                    source_authority is None
                    or source_authority["kind"] != "issuer"
                )
            )
            or (
                entry.get("method") in {"consensus-backed-proxy", "evm-rpc"}
                and (
                    source_authority is None
                    or source_authority["kind"] != "validator-set"
                    or source_identity[0] != "substrate-validator-set"
                )
            )
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

    provenance_by_result = {}
    for entry in result_provenance:
        if not isinstance(entry, dict) or set(entry) != {
            "ref", "serializedArtifactHash", "currentProductions",
            "cachedOrigins",
        }:
            return None
        reference = entry.get("ref")
        reference_key = canonical_bytes(reference)
        artifact_hash = entry.get("serializedArtifactHash")
        productions = entry.get("currentProductions")
        cached = entry.get("cachedOrigins")
        key = (reference_key, artifact_hash)
        if (
            not well_formed_result_ref(reference)
            or result_hash_by_ref.get(reference_key) != artifact_hash
            or not isinstance(productions, list)
            or not isinstance(cached, list)
            or not productions and not cached
            or key in provenance_by_result
        ):
            return None
        seen_productions = set()
        for production in productions:
            if not isinstance(production, dict) or set(production) != {
                "invocation", "requirementHash", "memberHash"
            }:
                return None
            values = (
                production.get("invocation"),
                production.get("requirementHash"),
                production.get("memberHash"),
            )
            if (
                not isinstance(values[0], str)
                or values[0] not in invocations
                or any(
                    not isinstance(value, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", value)
                    for value in values[1:]
                )
                or values in seen_productions
            ):
                return None
            seen_productions.add(values)
        seen_cached = set()
        for origin in cached:
            if not isinstance(origin, dict):
                return None
            presence = origin.get("parametersPresence")
            if presence == "absent":
                if set(origin) != {"parametersPresence"}:
                    return None
                canonical = b"absent"
            elif presence == "present":
                if set(origin) != {"parametersPresence", "parameters"} or not isinstance(
                    origin.get("parameters"), dict
                ):
                    return None
                try:
                    canonical = b"present:" + canonical_bytes(origin["parameters"])
                except (TypeError, ValueError, UnicodeError, RecursionError):
                    return None
            else:
                return None
            if canonical in seen_cached:
                return None
            seen_cached.add(canonical)
        provenance_by_result[key] = entry
    # Provenance is required at the point a non-pass result is reused.  The
    # authenticated artifact registry can also contain results for schemes
    # that are deliberately absent from a malformed requirement, so reject
    # unknown provenance here without requiring unrelated artifacts to carry
    # an invented requirement/member binding.
    if not set(provenance_by_result).issubset({
        (reference_key, artifact_hash)
        for reference_key, artifact_hash in result_hash_by_ref.items()
    }):
        return None
    return {
        "authorityByFamily": authority_by_family,
        "attestationByKey": attestation_by_key,
        "resultHashByRef": result_hash_by_ref,
        "provenanceByResult": provenance_by_result,
    }


@dataclass(frozen=True)
class VetAdmissionCapability:
    """One verifier-owned, nonce-consuming admission for nested Vet checks."""

    invocation_id: str
    challenge_id: str
    challenge_issued_at: int
    nonce: str
    presentation_bytes: bytes
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
    verifier_identity_challenge_id: str | None
    trusted_now: int
    session_start: str
    record_receipt_id: str | None
    record_anchor_binding: dict | None
    registered_schemes: frozenset[str]
    compatibility_requirement_hash: str | None


@dataclass(frozen=True)
class VerifierIdentityAdmissionCapability:
    """A separate nonce-consuming admission for the verifier's presentation."""

    invocation_id: str
    challenge_id: str
    challenge_issued_at: int
    nonce: str
    presentation_bytes: bytes
    job_id: str
    actor: str
    presented_party: str
    phase_index: int
    attempt: int
    issued_by: str
    trusted_now: int


@dataclass(frozen=True)
class VetInputAdmissionCapability:
    """Opaque verifier-owned evidence that the candidate crossed CF-5."""

    owner: object
    value: dict
    source: str
    raw_sha256: str | None


class VetReferenceRuntime:
    """Mutable offline runtime; caller payloads cannot reset its nonce ledger."""

    _INVOCATION_REQUIRED_FIELDS = {
        "jobId", "sessionStart", "sessionState", "phaseKind", "phaseIndex",
        "attempt", "actor", "evaluatedParty", "primaryClaim",
        "expectedVerifierRole",
        "expectedVerifier", "phaseOrchestrator", "anchorWriter",
        "recipeRegistryVersion", "challengeId", "verifierIdentityChallengeId",
        "trustedNow",
        "recordReceiptId", "recordAnchorBinding",
    }
    _INVOCATION_OPTIONAL_FIELDS = {
        "compatibilityProfile", "compatibilityRequirementHash",
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
        self.compatibility_profiles = trusted_context.get(
            "deferredSchemeCompatibilityProfiles", {}
        )
        self.nonce_ledger = NonceLedger(
            trusted_context.get("nonceIssuances"), registered_schemes=KNOWN_SCHEMES
        )
        self._input_admission_owner = object()

    def _registered_schemes(self, context):
        """Resolve a verifier-owned fixture profile; candidates cannot select it."""

        profile_id = context.get("compatibilityProfile")
        if profile_id is None:
            return frozenset(KNOWN_SCHEMES)
        if (
            not isinstance(profile_id, str)
            or not profile_id
            or not isinstance(self.compatibility_profiles, dict)
        ):
            return None
        profile = self.compatibility_profiles.get(profile_id)
        if (
            not isinstance(profile, dict)
            or set(profile) != {"registeredSchemes", "scope"}
            or profile.get("scope") != "fixture-only exact-scheme comparison"
            or not isinstance(profile.get("registeredSchemes"), list)
            or not profile["registeredSchemes"]
            or any(
                not isinstance(scheme, str)
                or not scheme
                or scheme in KNOWN_SCHEMES
                for scheme in profile["registeredSchemes"]
            )
            or len(set(profile["registeredSchemes"]))
            != len(profile["registeredSchemes"])
        ):
            return None
        return frozenset(KNOWN_SCHEMES | set(profile["registeredSchemes"]))

    @staticmethod
    def _compatibility_binding_valid(context):
        """A profile is admitted only with its exact verifier-bound requirement.

        Current-only invocations carry neither optional member.
        """

        bound = context.get("compatibilityRequirementHash")
        if (context.get("compatibilityProfile") is None) != (bound is None):
            return False
        return bound is None or (
            isinstance(bound, str)
            and re.fullmatch(r"[0-9a-f]{64}", bound) is not None
        )

    def admit_external_input(self, raw):
        value = integral_numbers(load_raw_json(raw))
        if not isinstance(value, dict):
            raise ValueError("Vet evaluation root must be an object")
        return value, VetInputAdmissionCapability(
            self._input_admission_owner,
            value,
            "external-bytes",
            hashlib.sha256(raw).hexdigest(),
        )

    def admit_synthetic_test_input(self, value):
        """Explicit admission for locally constructed conformance tests only."""

        admitted = integral_numbers(value)
        if not isinstance(admitted, dict):
            raise ValueError("synthetic Vet evaluation root must be an object")
        return admitted, VetInputAdmissionCapability(
            self._input_admission_owner, admitted, "synthetic-test", None
        )

    def owns_input(self, value, admission):
        return (
            isinstance(admission, VetInputAdmissionCapability)
            and admission.owner is self._input_admission_owner
            and admission.value is value
        )

    def derive_input(self, parent, admission, child):
        if (
            not self.owns_input(parent, admission)
            or not isinstance(parent, dict)
            or parent.get("input") is not child
        ):
            raise ValueError("input is not inside the admitted evaluation")
        return VetInputAdmissionCapability(
            self._input_admission_owner,
            child,
            admission.source,
            admission.raw_sha256,
        )

    def _trusted_invocation(self, invocation_id):
        context = self.invocations.get(invocation_id)
        if (
            not isinstance(context, dict)
            or not self._INVOCATION_REQUIRED_FIELDS <= set(context)
            or set(context) - self._INVOCATION_REQUIRED_FIELDS
            - self._INVOCATION_OPTIONAL_FIELDS
        ):
            return None
        if self._registered_schemes(context) is None:
            return None
        if not self._compatibility_binding_valid(context):
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
            or (
                context.get("verifierIdentityChallengeId") is not None
                and not isinstance(context["verifierIdentityChallengeId"], str)
            )
            or context.get("verifierIdentityChallengeId") == context.get("challengeId")
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
        if (receipt_id is None) != (
            context.get("verifierIdentityChallengeId") is None
        ):
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
        registered_schemes = self._registered_schemes(context)
        if registered_schemes is None:
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
        try:
            presentation_bytes = canonical_bytes(bundle)
        except (TypeError, ValueError, UnicodeError):
            return None
        return VetAdmissionCapability(
            invocation_id,
            context["challengeId"],
            issuance.issued_at,
            issuance.nonce,
            presentation_bytes,
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
            context["verifierIdentityChallengeId"],
            context["trustedNow"],
            context["sessionStart"],
            context["recordReceiptId"],
            copy.deepcopy(context["recordAnchorBinding"]),
            registered_schemes,
            context.get("compatibilityRequirementHash"),
        )

    def admit_verifier_identity(self, authority, bundle):
        if not isinstance(authority, dict):
            return None
        invocation_id = authority.get("invocation")
        if not isinstance(invocation_id, str):
            return None
        context = self._trusted_invocation(invocation_id)
        if context is None:
            return None
        challenge_id = context["verifierIdentityChallengeId"]
        if not isinstance(challenge_id, str):
            return None
        try:
            issuance = self.nonce_ledger.consume(
                challenge_id,
                presentation_nonce(bundle),
                context["trustedNow"],
            )
        except NonceRejected:
            return None
        if (
            issuance.job_id != context["jobId"]
            or issuance.actor != context["actor"]
            or issuance.evaluated_party != context["expectedVerifier"]
            or issuance.phase_index != context["phaseIndex"]
            or issuance.attempt != context["attempt"]
            or issuance.expected_verifier != context["phaseOrchestrator"]
            or issuance.issued_by != context["phaseOrchestrator"]
            or not isinstance(bundle, dict)
            or bundle.get("presentedBy") != context["expectedVerifier"]
        ):
            return None
        try:
            presentation_bytes = canonical_bytes(bundle)
        except (TypeError, ValueError, UnicodeError):
            return None
        return VerifierIdentityAdmissionCapability(
            invocation_id,
            challenge_id,
            issuance.issued_at,
            issuance.nonce,
            presentation_bytes,
            context["jobId"],
            context["actor"],
            issuance.evaluated_party,
            context["phaseIndex"],
            context["attempt"],
            issuance.issued_by,
            context["trustedNow"],
        )


def canonical_distinct_identity_claims(
    claims, identity, *, registered_schemes=None
):
    schemes = KNOWN_SCHEMES if registered_schemes is None else registered_schemes
    return {
        canonical_bytes(item) for item in claims
        if parse_ref(item.get("ref"), schemes) == identity
    }


def verifier_identity_has_exact_key_control(
    bundle, expected_verifier, *, registered_schemes=None
):
    """Require the verifier's exact expected key to sign its presentation."""

    schemes = KNOWN_SCHEMES if registered_schemes is None else registered_schemes
    try:
        expected = parse_ref(expected_verifier, schemes)
        presented = parse_ref(bundle.get("presentedBy"), schemes)
        claim_matches = canonical_distinct_identity_claims(
            bundle.get("claims", []),
            expected,
            registered_schemes=schemes,
        )
        signer_identities = [
            parse_ref(item.get("ref"), schemes)
            for item in bundle.get("presentation", {}).get("signatures", [])
        ]
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return False
    return (
        expected[0] == "key"
        and presented == expected
        and len(claim_matches) == 1
        and expected in signer_identities
    )


def signature_ref_matches_claim(
    signature_ref, claims, *, registered_schemes=None
):
    """CORE CF-3 signer membership in this bundle's claim identities."""

    schemes = KNOWN_SCHEMES if registered_schemes is None else registered_schemes
    try:
        signer_identity = parse_ref(signature_ref, schemes)
        return any(
            parse_ref(item.get("ref"), schemes) == signer_identity
            for item in claims
        )
    except (AttributeError, TypeError, ValueError):
        return False


def verify_bundle(bundle, admission=None, *, registered_schemes=None):
    if not isinstance(bundle, dict) or not all_safe_integers(bundle):
        return False
    if not {
        "bundleVersion", "presentedBy", "presentedAt", "claims", "presentation"
    } <= set(bundle):
        return False
    try:
        presentation_bytes = canonical_bytes(bundle)
    except (TypeError, ValueError, UnicodeError):
        return False
    if (
        bundle.get("bundleVersion") != "1"
        # presentedAt is a diagnostic `number`, not freshness authority.
        or not safe_number(bundle.get("presentedAt"))
        or (
            admission is not None
            and presentation_nonce(bundle) != admission.nonce
        )
        or (
            admission is not None
            and presentation_bytes != admission.presentation_bytes
        )
        or (
            isinstance(admission, VetAdmissionCapability)
            and bundle.get("presentedBy") != admission.primary_claim
        )
        or (
            isinstance(admission, VerifierIdentityAdmissionCapability)
            and bundle.get("presentedBy") != admission.presented_party
        )
    ):
        return False
    claims = bundle.get("claims")
    if (
        not isinstance(claims, list)
        or not claims
        or any(not isinstance(item, dict) for item in claims)
        # The claim times feed both matching and the §6.3.2 window, so a
        # non-integer value must not read as expired in one and absent in the
        # other (same rule as the presence-only reference consumer).
        or any(
            field in item and not safe_number(item[field])
            for item in claims
            for field in ("issuedAt", "expiresAt")
        )
    ):
        return False
    try:
        schemes = (
            admission.registered_schemes
            if isinstance(admission, VetAdmissionCapability)
            else KNOWN_SCHEMES if registered_schemes is None else registered_schemes
        )
        # A well-formed presentedBy is required structurally, but whether it
        # resolves to exactly one signed BundleClaim is a semantic BR-5/MA-3
        # predicate.  Keeping that distinction lets an otherwise authenticated
        # bundle produce fail instead of being misclassified as malformed.
        parse_ref(bundle.get("presentedBy"), schemes)
        for item in claims:
            parse_ref(item.get("ref"), schemes)
    except (AttributeError, ValueError):
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
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return False
    signatures_valid = all(
        isinstance(item, dict)
        and set(item) == {"ref", "signature"}
        and isinstance(item.get("ref"), str)
        and signature_ref_matches_claim(
            item.get("ref"), claims, registered_schemes=schemes
        )
        and verify_signature(item["ref"], item.get("signature"), payload)
        for item in signatures
    )
    return signatures_valid and (
        not isinstance(admission, VerifierIdentityAdmissionCapability)
        or verifier_identity_has_exact_key_control(
            bundle,
            admission.presented_party,
            registered_schemes=registered_schemes,
        )
    )


def verify_result(resolved, recipes, result_context):
    if (
        not isinstance(resolved, dict)
        or set(resolved) != {"ref", "artifact", "serializedArtifactHash"}
        or not isinstance(result_context, dict)
        or not within_json_depth(resolved.get("artifact"))
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
        # An unsupported VerifyResult version is refused before use (CORE
        # §11.1.2 new-type refusal), never read as version 1.
        artifact.get("resultVersion") != "1"
        # §7.5 required member types.  A malformed signed result keeps its
        # rejected disposition (CRQ-1) whether or not it is also stale.
        or artifact.get("decision") not in ("pass", "fail", "indeterminate", "error")
        or not isinstance(artifact.get("reason"), str)
        or ("data" in artifact and not isinstance(artifact["data"], dict))
        or not isinstance(artifact.get("scheme"), str)
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
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return False
    if unsigned_hash != reference["contentHash"]:
        return False
    method = artifact.get("method")
    family = (
        artifact.get("scheme"), method, artifact.get("recipeVersion")
    )
    if method not in KNOWN_METHODS or not isinstance(recipes, dict):
        return False
    recipe = recipe_for_method_version(recipes, *family)
    if recipe is None:
        return False
    selected_method = next(
        item for item in recipe_methods(recipe) if item["kind"] == method
    )
    authority = result_context["authorityByFamily"].get(family)
    authenticated_full_hash = result_context["resultHashByRef"].get(
        reference_key
    )
    source_attestation = result_context["attestationByKey"].get(
        attestation_key
    )
    issuer_allow_list = selected_method.get("issuerAllowList")
    source_authority = (
        source_attestation.get("sourceAuthority")
        if isinstance(source_attestation, dict)
        else None
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
        or source_attestation["resolvedSourceHash"]
        != artifact["attestation"]["contentHash"]
        or (
            method == "verifiable-credential"
            and issuer_allow_list is not None
            and (
                source_authority is None
                or source_authority.get("kind") != "issuer"
                or source_authority.get("claim") not in issuer_allow_list
            )
        )
        or resolved.get("serializedArtifactHash") != full_hash
        or authenticated_full_hash != full_hash
        or not safe_number(artifact.get("fetchedAt"))
        or not safe_number(artifact.get("verifiedAt"))
        # validUntil is optional; when absent, result_outcome falls back to
        # the exact recipe's defaultMaxAgeSec (DACS-1 §6.3.2, VP-C1).
        or (
            "validUntil" in artifact
            and not safe_number(artifact["validUntil"])
        )
        or artifact["fetchedAt"] > artifact["verifiedAt"]
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


def same_identity(left, right, registered_schemes=None):
    """CORE CF-3: parameters never contribute to a ClaimReference identity."""

    try:
        return parse_ref(left, registered_schemes) == parse_ref(
            right, registered_schemes
        )
    except ValueError:
        return False


def presented_claim(bundle, registered_schemes=None):
    """DACS-1 §6.3.2: the unique claim ``presentedBy`` resolves to by CF-3
    identity (canonical scheme and identifier).  Ambiguity resolves nothing."""

    matches = {
        canonical_bytes(item): item for item in bundle["claims"]
        if same_identity(
            item.get("ref"), bundle.get("presentedBy"), registered_schemes
        )
    }
    return next(iter(matches.values())) if len(matches) == 1 else None


def matching_claims(
    value, req, decision_time, exact_ref=None, *, registered_schemes=None
):
    now = decision_time
    matches = []
    for item in value["bundle"]["claims"]:
        scheme, _ = parse_ref(item.get("ref"), registered_schemes)
        if scheme != req.get("scheme"):
            continue
        if exact_ref is not None and not same_identity(
            item.get("ref"), exact_ref, registered_schemes
        ):
            continue
        expires_at = item.get("expiresAt")
        if expires_at is not None and (
            not safe_number(expires_at) or now > expires_at
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
    owner = owning_recipe_family(recipes, req.get("scheme"), method)
    if owner is None:
        return None
    family = sorted(
        version
        for scheme, family_method, version in recipes
        if scheme == req.get("scheme") and family_method == owner
    )
    if not family:
        return None
    if "recipeVersion" in req:
        expected = req["recipeVersion"]
        recipe = recipes.get((req.get("scheme"), owner, expected))
        if (
            recipe is None
            or not any(
                item["kind"] == method for item in recipe_methods(recipe)
            )
            or recipe.get("availability")
            in NON_OPERATIONAL_EXPLICIT_AVAILABILITIES
        ):
            return None
        return expected
    expected = family[-1]
    recipe = recipes.get((req.get("scheme"), owner, expected))
    if (
        recipe is None
        or recipe.get("availability") != "live"
        or not any(item["kind"] == method for item in recipe_methods(recipe))
    ):
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


def result_outcome(
    value, claim, req, recipes, result_context, decision_time,
    *, registered_schemes=None,
):
    """DACS-1 §6.3.2: resolve the claim's own ``verifiedBy`` and qualify it."""

    reference = claim.get("verifiedBy")
    if not well_formed_result_ref(reference):
        return "fail" if reference is None else "error"
    results = resolved_by_ref(value)
    if results is None:
        return "error"
    resolved = results.get(canonical_bytes(reference))
    if resolved is None:
        return "indeterminate"
    return qualify_result(
        resolved,
        claim,
        req,
        recipes,
        result_context,
        decision_time,
        value,
        registered_schemes=registered_schemes,
    )


def freshness_window(result, claim, recipes, decision_time):
    """DACS-1 §6.3.2 governing window of ``result`` for ``claim``.

    Expiry is ``min(claim.expiresAt, validUntil ?? verifiedAt + the exact
    recipe's defaultMaxAgeSec)``.  Returns "current", "stale" (expired or an
    inverted, undeterminable window) or "untimed" (non-integer times).  CRQ-1:
    only results whose governing window has passed take part in qualification
    preflight or classification.
    """

    verified_at = result.get("verifiedAt")
    if "validUntil" in result:
        valid_until = result["validUntil"]
    else:
        # The exact recipe the result was validated under, never "latest".
        recipe = recipe_for_method_version(
            recipes,
            result.get("scheme"),
            result.get("method"),
            result.get("recipeVersion"),
        )
        valid_until = (
            verified_at + recipe["defaultMaxAgeSec"] * 1_000
            if recipe is not None and safe_number(verified_at)
            else None
        )
    if not safe_number(verified_at) or not safe_number(valid_until):
        return "untimed"
    expires_at = claim.get("expiresAt")
    effective_expiry = min(
        valid_until,
        expires_at if safe_number(expires_at) else SAFE_INT,
    )
    if valid_until < verified_at or decision_time > effective_expiry:
        return "stale"
    return "current"


ACTIVE_INVOCATION = object()
ACTIVE_REQUIREMENT_HASH = object()


def non_pass_origin_is_eligible(resolved, req, result_context, value):
    """Apply VP-C1 using verifier-owned provenance, never candidate labels."""

    try:
        key = (
            canonical_bytes(resolved["ref"]),
            resolved["serializedArtifactHash"],
        )
        provenance = result_context["provenanceByResult"][key]
        invocation = value.get(ACTIVE_INVOCATION)
        requirement_hash = value.get(ACTIVE_REQUIREMENT_HASH)
        member_hash = hash_hex(req)
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError):
        return False
    if isinstance(invocation, str) and isinstance(requirement_hash, str) and any(
        item["invocation"] == invocation
        and item["requirementHash"] == requirement_hash
        and item["memberHash"] == member_hash
        for item in provenance["currentProductions"]
    ):
        return True
    present = "parameters" in req
    parameters = req.get("parameters")
    for origin in provenance["cachedOrigins"]:
        if present != (origin["parametersPresence"] == "present"):
            continue
        if not present or canonical_bytes(origin["parameters"]) == canonical_bytes(
            parameters
        ):
            return True
    return False


def qualify_result(
    resolved, claim, req, recipes, result_context, decision_time, value,
    *, registered_schemes=None,
):
    """Authenticate one resolved result and qualify it for ``claim``/``req``."""

    if not verify_result(resolved, recipes, result_context):
        return "error"
    reference = resolved["ref"]
    result = resolved["artifact"]
    scheme, identifier = parse_ref(claim["ref"], registered_schemes)
    if (
        result.get("scheme") != scheme
        or result.get("identifier") != identifier
        or result.get("recipeVersion") != reference["recipeVersion"]
    ):
        return "fail"
    window = freshness_window(result, claim, recipes, decision_time)
    if window == "untimed":
        return "fail"
    if window == "stale":
        # Not current evidence, so it cannot reach family/version preflight.
        return "not-applicable"
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
    if decision != "pass" and not non_pass_origin_is_eligible(
        resolved, req, result_context, value
    ):
        return "qualification-error"
    now = decision_time
    verified_at = result["verifiedAt"]
    if verified_at > now:
        return "error"
    max_age = req.get("maxAge")
    if max_age is not None and now > verified_at + max_age * 1_000:
        return "not-applicable"
    if decision == "pass" and not parameters_match(result, req):
        return "fail"
    return decision


# Only authenticate_production_aggregate sets this key.  It is an object, not
# a string, so no caller-supplied JSON input can select aggregation semantics.
COMMITTED_RESULTS_ONLY = object()


def committed_results(value, req):
    """DACS-2 §7.7.1 find_all_results(record, cr.scheme) over the committed set."""

    return [
        item for item in value["resolvedResults"]
        if item["artifact"].get("scheme") == req.get("scheme")
    ]


def member_outcomes(
    value, req, recipes, result_context, decision_time, exact_ref=None,
    *, registered_schemes=None,
):
    """Per-evidence outcomes for one verified member.

    Direct DACS-1 evaluation follows each matching claim's own ``verifiedBy``.
    Aggregation (§7.7.1 classify_verified_member) instead classifies every
    result the signed record commits for the scheme, so a refreshed result
    counts and an uncommitted pointer does not.  Each committed result still
    needs an unexpired matching claim of the exact bundle: the claim's
    ``expiresAt`` is half of the §6.3.2 freshness window, and a result for
    another identity is not evidence for this member.  Such a result does not
    participate (CRQ-2/CRQ-4), so it can neither satisfy the member nor steer
    its decision or VPC-4 fault class.
    """

    claims = matching_claims(
        value,
        req,
        decision_time,
        exact_ref,
        registered_schemes=registered_schemes,
    )
    if not value.get(COMMITTED_RESULTS_ONLY):
        return [
            result_outcome(
                value,
                claim,
                req,
                recipes,
                result_context,
                decision_time,
                registered_schemes=registered_schemes,
            )
            for claim in claims
        ]
    outcomes = []
    for resolved in committed_results(value, req):
        artifact = resolved["artifact"]
        identity = (artifact.get("scheme"), artifact.get("identifier"))
        owners = [
            claim for claim in claims
            if parse_ref(claim["ref"], registered_schemes) == identity
        ]
        if not owners:
            outcomes.append("not-applicable")
            continue
        outcomes.extend(
            qualify_result(
                resolved, claim, req, recipes, result_context, decision_time,
                value, registered_schemes=registered_schemes,
            )
            for claim in owners
        )
    return outcomes


def classify_member(
    value, req, recipes, result_context, decision_time, exact_ref=None,
    *, registered_schemes=None,
):
    if req.get("verificationRequired") is False:
        matches = matching_claims(
            value,
            req,
            decision_time,
            exact_ref,
            registered_schemes=registered_schemes,
        )
        return "pass" if matches else "fail"
    parameters = req.get("parameters") or {}
    selected_method = parameters.get("verificationMethod")
    if (
        selected_method is not None
        and effective_recipe_version(req, selected_method, recipes) is None
    ):
        return "error"
    outcomes = member_outcomes(
        value,
        req,
        recipes,
        result_context,
        decision_time,
        exact_ref,
        registered_schemes=registered_schemes,
    )
    if "qualification-error" in outcomes:
        return "error"
    for outcome in ("pass", "fail", "error", "indeterminate"):
        if outcome in outcomes:
            return outcome
    return "fail"


def qualification_preflight(
    value, req, recipes, result_context, decision_time, *, registered_schemes=None
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
    if value.get(COMMITTED_RESULTS_ONLY):
        # §7.7.1 preflight_qualification: every method the record commits for
        # this scheme must resolve, whether or not a bundle claim cites it --
        # but only for results that are current evidence (CRQ-1): owned by an
        # unexpired claim with its identity and inside their governing window.
        claims = matching_claims(
            value, req, decision_time, registered_schemes=registered_schemes
        )
        current = [
            item for item in committed_results(value, req)
            if any(
                parse_ref(claim["ref"], registered_schemes)
                == (item["artifact"].get("scheme"), item["artifact"].get("identifier"))
                and freshness_window(item["artifact"], claim, recipes, decision_time)
                == "current"
                for claim in claims
            )
        ]
        methods = (
            {selected_method} if selected_method is not None
            else {item["artifact"].get("method") for item in current}
        )
        return all(
            effective_recipe_version(req, method, recipes) is not None
            for method in methods
        ) and all(
            item["artifact"].get("decision") == "pass"
            or non_pass_origin_is_eligible(item, req, result_context, value)
            for item in current
        )
    return all(
        result_outcome(
            value,
            claim,
            req,
            recipes,
            result_context,
            decision_time,
            registered_schemes=registered_schemes,
        )
        != "qualification-error"
        for claim in matching_claims(
            value, req, decision_time, registered_schemes=registered_schemes
        )
    )


def claim_establishes_control(
    value, claim, recipes, result_context, decision_time, *, registered_schemes=None
):
    """Return whether this exact claim proves holder control (BR-5/PCR-5)."""

    bundle = value["bundle"]
    scheme, _ = parse_ref(claim["ref"], registered_schemes)
    signer_refs = [item["ref"] for item in bundle["presentation"]["signatures"]]
    if scheme == "key":
        return any(
            same_identity(ref, claim["ref"], registered_schemes)
            for ref in signer_refs
        )
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
    data = result.get("data")
    binding = data.get("holderBinding") if isinstance(data, dict) else None
    return (
        result_outcome(
            value,
            claim,
            {"scheme": scheme, "verificationRequired": True,
             "recipeVersion": reference["recipeVersion"]},
            recipes,
            result_context,
            decision_time,
            registered_schemes=registered_schemes,
        ) == "pass"
        and result.get("method") == "verifiable-credential"
        and isinstance(binding, dict)
        and any(
            same_identity(
                binding.get("controller"), ref, registered_schemes
            )
            for ref in signer_refs
        )
    )


def presented_control(
    value, recipes, result_context, decision_time, *, registered_schemes=None
):
    """DACS-1 §6.3.2 step (6) control of the exact presented claim."""

    claim = presented_claim(value["bundle"], registered_schemes)
    return claim is not None and claim_establishes_control(
        value,
        claim,
        recipes,
        result_context,
        decision_time,
        registered_schemes=registered_schemes,
    )


def exact_verified_selector(
    value, presented, selector, recipes, result_context, decision_time,
    *, registered_schemes=None,
):
    """Return whether the selected claim has exact passing, fresh evidence."""

    reference = presented.get("verifiedBy")
    return well_formed_result_ref(reference) and result_outcome(
        value,
        presented,
        {"scheme": selector, "verificationRequired": True,
         "recipeVersion": reference["recipeVersion"]},
        recipes,
        result_context,
        decision_time,
        registered_schemes=registered_schemes,
    ) == "pass"


def selector_authorization_facts(
    value, req, recipes, result_context, decision_time, *, registered_schemes=None
):
    """Expose the historical facts used by exact_selector_authorized.

    Production authorization needs to preserve the selector's signed-decision
    presence branch while requalifying exact result-backed control and verified
    evidence at trustedNow.  Keeping the three facts separate prevents that
    current-time check from rerunning presence matching under a later time.
    """

    selector = req.get("primaryClaimSelector")
    if selector is None:
        return {
            "selector_present": False,
            "presented": None,
            "controlled": True,
            "verified_selector": False,
            "presence_selector": False,
        }
    bundle = value["bundle"]
    scheme, _ = parse_ref(bundle["presentedBy"], registered_schemes)
    presented = presented_claim(bundle, registered_schemes)
    if scheme != selector or presented is None:
        return {
            "selector_present": True,
            "presented": presented,
            "controlled": False,
            "verified_selector": False,
            "presence_selector": False,
        }
    controlled = claim_establishes_control(
        value,
        presented,
        recipes,
        result_context,
        decision_time,
        registered_schemes=registered_schemes,
    )
    if not controlled:
        return {
            "selector_present": True,
            "presented": presented,
            "controlled": False,
            "verified_selector": False,
            "presence_selector": False,
        }
    required = req.get("required", [])
    one_of = req.get("oneOf", [])

    def is_selector(member, verified):
        return (
            member.get("scheme") == selector
            and member.get("verificationRequired") is verified
        )

    def exact_presence(member):
        return classify_member(
            value, member, recipes, result_context, decision_time,
            exact_ref=presented["ref"],
            registered_schemes=registered_schemes,
        ) == "pass"

    # verifiedSelector: passing, fresh exact-claim evidence under the DACS-1
    # §6.3.2 verified-claim gate.  It is member-independent, and another
    # same-scheme claim cannot supply it (PCR-5).
    verified_selector = exact_verified_selector(
        value,
        presented,
        selector,
        recipes,
        result_context,
        decision_time,
        registered_schemes=registered_schemes,
    )

    presence_selector = any(
        is_selector(item, False) and exact_presence(item)
        for item in [*required, *(member for group in one_of for member in group)]
    )
    if any(is_selector(item, True) for item in required):
        presence_selector = False
    for group in one_of:
        if not any(is_selector(item, True) for item in group):
            continue
        # A group that also admits the selector scheme through verification
        # must itself be satisfied by exact presence or by another scheme, so
        # a different same-scheme verified claim cannot launder the selector.
        exact_presence_in_group = any(
            is_selector(item, False) and exact_presence(item) for item in group
        )
        passing_other_scheme = any(
            item.get("scheme") != selector
            and classify_member(
                value,
                item,
                recipes,
                result_context,
                decision_time,
                registered_schemes=registered_schemes,
            ) == "pass"
            for item in group
        )
        if not (exact_presence_in_group or passing_other_scheme):
            presence_selector = False
    return {
        "selector_present": True,
        "presented": presented,
        "controlled": controlled,
        "verified_selector": verified_selector,
        "presence_selector": presence_selector,
    }


def selector_authorized(
    value, req, recipes, result_context, decision_time, *, registered_schemes=None
):
    """DACS-2 §7.7.1 exact_selector_authorized over the exact presented claim."""

    facts = selector_authorization_facts(
        value,
        req,
        recipes,
        result_context,
        decision_time,
        registered_schemes=registered_schemes,
    )
    return (
        not facts["selector_present"]
        or facts["controlled"]
        and (facts["verified_selector"] or facts["presence_selector"])
    )


def current_presenter_controlled(
    value, presented, historically_controlled, recipes, result_context,
    decision_time, *, registered_schemes=None,
):
    """Requalify one historically controlled exact presenter at trustedNow."""

    return not historically_controlled or claim_establishes_control(
        value,
        presented,
        recipes,
        result_context,
        decision_time,
        registered_schemes=registered_schemes,
    )


def current_selector_authorized(
    value, req, historical_facts, recipes, result_context, decision_time,
    *, registered_schemes=None,
):
    """Requalify only a historically authorized selector for progression.

    The signed-decision presence arm remains historical.  Exact result-backed
    control and verified-selector evidence are requalified at trustedNow, but
    a selector that was historically absent or unauthorized remains an
    evaluation outcome rather than becoming an aggregation-authority error.
    """

    historically_authorized = (
        historical_facts["selector_present"]
        and historical_facts["controlled"]
        and (
            historical_facts["verified_selector"]
            or historical_facts["presence_selector"]
        )
    )
    if not historically_authorized:
        return True
    presented = historical_facts["presented"]
    return current_presenter_controlled(
        value,
        presented,
        True,
        recipes,
        result_context,
        decision_time,
        registered_schemes=registered_schemes,
    ) and (
        historical_facts["presence_selector"]
        or exact_verified_selector(
            value,
            presented,
            req["primaryClaimSelector"],
            recipes,
            result_context,
            decision_time,
            registered_schemes=registered_schemes,
        )
    )


def valid_requirement(req, registered_schemes=None):
    try:
        canonical_bytes(req)
    except (TypeError, ValueError, UnicodeError):
        return False
    if (
        not isinstance(req, dict)
        or req.get("requirementVersion") != "1"
        or not all_safe_integers(req)
        or (
            "primaryClaimSelector" in req
            and (
                not isinstance(req["primaryClaimSelector"], str)
                or not req["primaryClaimSelector"]
            )
        )
        or (
            "preferredPresentation" in req
            and (
                not isinstance(req["preferredPresentation"], str)
                or req["preferredPresentation"] not in {
                    "siwd", "sr1-root", "per-claim", "session-key", "any"
                }
            )
        )
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
            or item.get("scheme") not in (
                KNOWN_SCHEMES
                if registered_schemes is None
                else registered_schemes
            )
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
                    not safe_number(item["maxAge"])
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


def compatibility_requirement_bound(req, admission):
    """Whether a deferred-scheme profile admits this exact requirement.

    The verifier-owned invocation binds the canonical requirement its fixture
    profile was issued for, so a candidate cannot carry the extra registered
    schemes to another requirement or to a requirement-free question.
    Current-only admissions carry no binding and are unaffected.
    """

    bound = admission.compatibility_requirement_hash
    if bound is None:
        return True
    try:
        return req is not None and hash_hex(req) == bound
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return False


def evaluate(value, recipes, result_context, *, decision_time, admission):
    if (
        not isinstance(value, dict)
        or not exact_safe_integer(decision_time, minimum=0)
        or not isinstance(admission, VetAdmissionCapability)
    ):
        return "error", ["invalid evaluation time"]
    req = value.get("requirement")
    # Runs after SN-4 consumption; a direct evaluation reaches it before the
    # bundle is interpreted under any profile-extended registry.
    if not compatibility_requirement_bound(req, admission):
        return "error", ["requirement is not bound to the compatibility profile"]
    if not verify_bundle(value.get("bundle"), admission):
        return "error", ["invalid identity bundle"]
    registered_schemes = admission.registered_schemes
    if not valid_requirement(req, registered_schemes):
        return "error", ["invalid bundle requirement"]
    value[ACTIVE_INVOCATION] = admission.invocation_id
    value[ACTIVE_REQUIREMENT_HASH] = hash_hex(req)
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
            value,
            member,
            recipes,
            result_context,
            decision_time,
            registered_schemes=registered_schemes,
        )
        for member in members
    ):
        return "error", ["unresolved recipe family or version"]
    failures = []
    errors = []
    indeterminates = []
    exact_presenter_controlled = presented_control(
        value,
        recipes,
        result_context,
        decision_time,
        registered_schemes=registered_schemes,
    )
    if req.get("primaryClaimSelector") is None and not exact_presenter_controlled:
        failures.append("presentedBy is uncontrolled")
    for item in req.get("required", []):
        outcome = classify_member(
            value,
            item,
            recipes,
            result_context,
            decision_time,
            registered_schemes=registered_schemes,
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
                value,
                item,
                recipes,
                result_context,
                decision_time,
                registered_schemes=registered_schemes,
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
    selector_is_authorized = (
        selector_authorized(
            value,
            req,
            recipes,
            result_context,
            decision_time,
            registered_schemes=registered_schemes,
        )
        if req.get("primaryClaimSelector") is not None
        else True
    )
    if req.get("primaryClaimSelector") is not None and (
        not exact_presenter_controlled or not selector_is_authorized
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


COMPOSITE_REQUIRED_FIELDS = {
    "recordVersion", "jobId", "evaluatedParty", "bundleHash",
    "requirementHash", "freshness", "supplementary", "dealSpecific",
    "overallDecision", "generatedAt", "signature",
}


def valid_composite_record_shape(record):
    """DACS-2 §7.7 required members, version literal, and warning types.

    An unsupported ``recordVersion`` is refused (CORE §11.1.2) rather than
    replayed under version-1 semantics.  Warnings stay advisory (WN-1), but a
    malformed warning list makes the signed record malformed.
    """

    if (
        not isinstance(record, dict)
        or not within_json_depth(record)
        or not COMPOSITE_REQUIRED_FIELDS <= set(record)
        or record.get("recordVersion") != "1"
    ):
        return False
    warnings = record.get("warnings", [])
    return isinstance(warnings, list) and all(
        isinstance(warning, dict)
        and isinstance(warning.get("claimRef"), str)
        and isinstance(warning.get("code"), str)
        and bool(warning["code"])
        and type(warning.get("retryable")) is bool
        and (
            "suggestedRetryAfterMs" not in warning
            or exact_safe_integer(warning["suggestedRetryAfterMs"], minimum=0)
        )
        for warning in warnings
    )


def results_without_verified_member(req, resolved):
    """Committed results no verified member can claim (DACS-2 §7.7.1).

    "Every CVR VerifyResultRef must be attributable to at least one verified
    member": presence-only members never invoke a recipe, so a committed
    result whose scheme only presence-only members (or no member) name is a
    synthetic or unrelated reference and rejects the record.
    """

    members = [
        *req.get("required", []),
        *(member for group in req.get("oneOf", []) for member in group),
    ]
    verified = {m["scheme"] for m in members if m["verificationRequired"] is True}
    return [
        item for item in resolved
        if item["artifact"]["scheme"] not in verified
    ]


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
    value, trusted_context, recipes, result_context, admission,
    verifier_identity_admission, runtime, *, authorize_current=True
):
    if not isinstance(value, dict) or not isinstance(trusted_context, dict):
        return None
    record = value.get("record")
    record_ref = value.get("recordRef")
    authority = value.get("authority")
    if (
        not valid_composite_record_shape(record)
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
    except (TypeError, ValueError, UnicodeError, RecursionError):
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
    except (AttributeError, TypeError, ValueError, UnicodeError, RecursionError):
        return None
    if (
        verifier_identity_admission is None
        or verifier_identity_admission.invocation_id != admission.invocation_id
        or verifier_identity_admission.job_id != admission.job_id
        or verifier_identity_admission.actor != admission.actor
        or verifier_identity_admission.phase_index != admission.phase_index
        or verifier_identity_admission.attempt != admission.attempt
        or verifier_identity_admission.presented_party != admission.expected_verifier
        or verifier_identity_admission.issued_by != admission.phase_orchestrator
        or verifier_identity_admission.trusted_now != admission.trusted_now
        or not verify_bundle(bundle, admission)
        or not verify_bundle(verifier_identity, verifier_identity_admission)
        or verifier_identity.get("presentedBy") != admission.expected_verifier
        or signature.get("signer") != admission.expected_verifier
        or record_ref.get("signer") != admission.expected_verifier
        or record.get("evaluatedParty") != admission.evaluated_party
        or record.get("evaluatedParty") != bundle.get("presentedBy")
        or record.get("bundleHash") != bound_bundle_hash
        or record.get("requirementHash") != requirement_hash
        or not exact_safe_integer(generated_at, minimum=0)
        or generated_at > admission.trusted_now
        or (
            authorize_current
            and generated_at < admission.challenge_issued_at
        )
        or (
            authorize_current
            and generated_at < verifier_identity_admission.challenge_issued_at
        )
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
    except (TypeError, ValueError, UnicodeError, RecursionError):
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
        # CRQ-1: one committed reference per result.  A second reference that
        # differs only in its recipeVersion label is a duplicate commitment.
        or any(
            item["ref"]["recipeVersion"] != item["artifact"]["recipeVersion"]
            for item in resolved
        )
        or len({item["ref"]["contentHash"] for item in resolved}) != len(resolved)
    ):
        return None
    # A malformed requirement keeps its own "invalid bundle requirement" error
    # in evaluate(); a well-formed one cannot carry presence-only results.
    if valid_requirement(req, admission.registered_schemes) and (
        results_without_verified_member(req, resolved)
    ):
        return None
    projection = {
        "bundle": bundle,
        "requirement": req,
        "resolvedResults": resolved,
        "decisionTime": generated_at,
        "authorizationTime": admission.trusted_now,
        # §7.7.1 classifies the record's committed results, not the bundle's
        # verifiedBy pointers.
        COMMITTED_RESULTS_ONLY: True,
    }
    if authorize_current and valid_requirement(req, admission.registered_schemes):
        historical_selector = selector_authorization_facts(
            projection,
            req,
            recipes,
            result_context,
            generated_at,
            registered_schemes=admission.registered_schemes,
        )
        historical_presented = presented_claim(
            bundle, admission.registered_schemes
        )
        historical_presenter_controlled = (
            historical_presented is not None
            and claim_establishes_control(
                projection,
                historical_presented,
                recipes,
                result_context,
                generated_at,
                registered_schemes=admission.registered_schemes,
            )
        )
        if (
            req.get("primaryClaimSelector") is None
            and not current_presenter_controlled(
                projection,
                historical_presented,
                historical_presenter_controlled,
                recipes,
                result_context,
                admission.trusted_now,
                registered_schemes=admission.registered_schemes,
            )
        ):
            return None
        if not current_selector_authorized(
            projection,
            req,
            historical_selector,
            recipes,
            result_context,
            admission.trusted_now,
            registered_schemes=admission.registered_schemes,
        ):
            return None
        verified_members = [
            *(
                member for member in req.get("required", [])
                if member.get("verificationRequired") is True
            ),
            *(
                member
                for group in req.get("oneOf", [])
                for member in group
                if member.get("verificationRequired") is True
            ),
        ]
        claims = bundle.get("claims", [])
        for resolved_item in resolved:
            artifact = resolved_item["artifact"]
            identity = (artifact.get("scheme"), artifact.get("identifier"))
            owners = [
                claim for claim in claims
                if isinstance(claim, dict)
                and same_identity(
                    claim.get("ref"),
                    f"{identity[0]}:{identity[1]}",
                    admission.registered_schemes,
                )
            ]
            for member in verified_members:
                if member.get("scheme") != artifact.get("scheme") or not owners:
                    continue
                parameters = member.get("parameters") or {}
                selected_method = parameters.get(
                    "verificationMethod", artifact.get("method")
                )
                if (
                    artifact.get("method") != selected_method
                    or artifact.get("recipeVersion")
                    != effective_recipe_version(member, selected_method, recipes)
                ):
                    continue
                max_age = member.get("maxAge")
                participating_owner = False
                for owner in owners:
                    # Results that were already outside their governing
                    # window or member maxAge at the signed decision time never
                    # participated; they remain inert during authorization.
                    if (
                        freshness_window(
                            artifact, owner, recipes, generated_at
                        ) != "current"
                        or (
                            max_age is not None
                            and generated_at
                            > artifact["verifiedAt"] + max_age * 1_000
                        )
                    ):
                        continue
                    participating_owner = True
                    if freshness_window(
                        artifact, owner, recipes, admission.trusted_now
                    ) != "current":
                        return None
                if (
                    participating_owner
                    and
                    max_age is not None
                    and admission.trusted_now
                    > artifact["verifiedAt"] + max_age * 1_000
                ):
                    return None
    return projection


def aggregate_output(
    value, trusted_context, recipes, result_context, runtime, *,
    input_admission, authorize_current=True
):
    try:
        if (
            not isinstance(runtime, VetReferenceRuntime)
            or runtime.trusted_context is not trusted_context
            or not runtime.owns_input(value, input_admission)
        ):
            raise ValueError("a verifier-owned runtime is required")
        active_runtime = runtime
        authority = value.get("authority") if isinstance(value, dict) else None
        vet_input = authority.get("vetInput") if isinstance(authority, dict) else None
        bundle = vet_input.get("bundleToVet") if isinstance(vet_input, dict) else None
        admission = active_runtime.admit(authority, bundle)
        verifier_identity_admission = active_runtime.admit_verifier_identity(
            authority,
            vet_input.get("verifierIdentity") if isinstance(vet_input, dict) else None,
        )
    except (AttributeError, TypeError, ValueError, UnicodeError, RecursionError):
        admission = None
        verifier_identity_admission = None
    if admission is None or verifier_identity_admission is None:
        return {"decision": "error", "reasons": ["aggregation authority invalid"]}
    try:
        projection = authenticate_production_aggregate(
            value,
            trusted_context,
            recipes,
            result_context,
            admission,
            verifier_identity_admission,
            active_runtime,
            authorize_current=authorize_current,
        )
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, RecursionError):
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
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, RecursionError):
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


def execute(evaluation, document, runtime, input_admission):
    operation = evaluation.get("operation") if isinstance(evaluation, dict) else None
    try:
        trusted_context = document["trustedContext"]
        if (
            not isinstance(runtime, VetReferenceRuntime)
            or runtime.trusted_context is not trusted_context
            or not runtime.owns_input(evaluation, input_admission)
        ):
            raise ValueError("a verifier-owned runtime is required")
        value = evaluation["input"]
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
                input_admission=active_runtime.derive_input(
                    evaluation, input_admission, value
                ),
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
            # A control decision has no requirement, so a requirement-bound
            # compatibility profile can never authorize one.
            if not compatibility_requirement_bound(
                None, admission
            ) or not verify_bundle(value.get("bundle"), admission):
                decision = "error"
            else:
                decision = (
                    "pass"
                    if presented_control(
                        value,
                        recipes,
                        result_context,
                        admission.trusted_now,
                        registered_schemes=admission.registered_schemes,
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
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, RecursionError):
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
    try:
        admitted, capability = runtime.admit_synthetic_test_input(evaluation)
    except (TypeError, ValueError, RecursionError):
        operation = evaluation.get("operation") if isinstance(evaluation, dict) else None
        if operation == "match":
            return False
        if operation in {"decision", "control-decision"}:
            return "error"
        if operation == "decision-no-throw":
            return {"decision": "error", "throws": False}
        if operation == "aggregate":
            return {"decision": "error", "reasons": ["invalid aggregation input"]}
        return "error"
    return execute(admitted, document, runtime=runtime, input_admission=capability)


def execute_external_once(raw, document):
    """Execute one exact received JSON evaluation after CF-5 admission."""

    runtime = VetReferenceRuntime(document["trustedContext"])
    try:
        admitted, capability = runtime.admit_external_input(raw)
    except (RawJsonProfileError, TypeError, ValueError):
        return "error"
    return execute(admitted, document, runtime=runtime, input_admission=capability)


def reconstruct_historical_once(evaluation, document):
    """Authenticate and reconstruct an aggregate without authorizing progress."""

    runtime = VetReferenceRuntime(document["trustedContext"])
    admitted, capability = runtime.admit_synthetic_test_input(evaluation)
    recipes = authenticated_recipe_registry(document)
    result_context = authenticated_result_context(document, recipes)
    return aggregate_output(
        admitted["input"],
        document["trustedContext"],
        recipes,
        result_context,
        runtime,
        input_admission=runtime.derive_input(
            admitted, capability, admitted["input"]
        ),
        authorize_current=False,
    )


def execute_case(case, document):
    runtime = VetReferenceRuntime(document["trustedContext"])
    observed = {}
    for name, evaluation in case["evaluations"].items():
        admitted, capability = runtime.admit_synthetic_test_input(evaluation)
        observed[name] = execute(
            admitted, document, runtime=runtime, input_admission=capability
        )
    return observed["result"] if list(observed) == ["result"] else observed


class Dacs1VetGoldenInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = FIXTURE.read_bytes()
        cls.document = load_raw_json(cls.raw)
        cls.cases = cls.document["cases"]
        cls.recipes = authenticated_recipe_registry(cls.document)
        cls.result_context = authenticated_result_context(
            cls.document, cls.recipes
        )

    def test_generator_is_deterministic(self):
        subprocess.run(
            ["python3", str(GENERATOR), "--check"], cwd=ROOT, check=True
        )

    def test_external_vet_entry_requires_exact_cf5_admission(self):
        _, evaluation = self._case_evaluation("vet-ma3-verified-accept")
        raw = json.dumps(
            evaluation, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertIs(True, execute_external_once(raw, self.document))

        invalid = (
            raw[:-1] + b',"probe":9007199254740991.1}',
            b'{"operation":"match","\\u006fperation":"match","input":{}}',
            b'{"operation":"match","input":{},"probe":"\\ud800"}',
            b"\xef\xbb\xbf" + raw,
            raw + b" trailing",
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate[:50]), mock.patch(
                __name__ + ".verify_signature", wraps=verify_signature
            ) as signature_check:
                self.assertEqual("error", execute_external_once(candidate, self.document))
                signature_check.assert_not_called()

        admitted = copy.deepcopy(evaluation)
        nested = None
        for _ in range(MAX_JSON_DEPTH - 1):
            nested = [nested]
        admitted["padding"] = nested
        depth_128 = json.dumps(admitted, separators=(",", ":")).encode("utf-8")
        self.assertIs(True, execute_external_once(depth_128, self.document))
        nested = [nested]
        admitted["padding"] = nested
        depth_129 = json.dumps(admitted, separators=(",", ":")).encode("utf-8")
        with mock.patch(__name__ + ".verify_signature", wraps=verify_signature) as check:
            self.assertEqual("error", execute_external_once(depth_129, self.document))
            check.assert_not_called()

        runtime = VetReferenceRuntime(self.document["trustedContext"])
        with self.assertRaises(TypeError):
            runtime.admit_external_input(raw.decode("utf-8"))
        # The public match projection is boolean, so an unadmitted value is
        # fail closed as False even though the internal decision is error.
        self.assertFalse(execute(evaluation, self.document, runtime, None))

    def test_source_authority_is_distinct_from_result_producer(self):
        vc = next(
            result
            for case in self.cases
            for evaluation in case["evaluations"].values()
            for result in evaluation["input"]["resolvedResults"]
            if result["artifact"]["method"] == "verifiable-credential"
        )
        proxy = next(
            result
            for case in self.cases
            for evaluation in case["evaluations"].values()
            for result in evaluation["input"]["resolvedResults"]
            if result["artifact"]["method"] == "consensus-backed-proxy"
        )
        signerless_source = copy.deepcopy(proxy)
        signerless_source["artifact"]["method"] = "tlsnotary"
        signerless_source["artifact"]["attestation"].pop("signer")
        signerless = resign_result(
            signerless_source, fixture_private_key("authority"), AUTHORITY_REF
        )
        signerless_context = copy.deepcopy(self.result_context)
        signerless_context["resultHashByRef"][
            canonical_bytes(signerless["ref"])
        ] = signerless["serializedArtifactHash"]
        signerless_context["attestationByKey"][
            canonical_bytes(signerless["artifact"]["attestation"])
        ] = {
            "attestation": copy.deepcopy(signerless["artifact"]["attestation"]),
            "resolvedSourceHash": signerless["artifact"]["attestation"][
                "contentHash"
            ],
            "scheme": signerless["artifact"]["scheme"],
            "method": "tlsnotary",
            "recipeVersion": signerless["artifact"]["recipeVersion"],
            "resultSigner": AUTHORITY_REF,
        }
        for resolved in (vc, proxy):
            self.assertTrue(verify_result(resolved, self.recipes, self.result_context))
        self.assertTrue(verify_result(signerless, self.recipes, signerless_context))
        self.assertEqual(VC_ISSUER_REF, vc["artifact"]["attestation"]["signer"])
        self.assertNotEqual(
            vc["artifact"]["attestation"]["signer"],
            vc["artifact"]["signature"]["signer"],
        )
        self.assertEqual(
            VALIDATOR_SET_REF, proxy["artifact"]["attestation"]["signer"]
        )
        self.assertNotIn("signer", signerless["artifact"]["attestation"])

        for label, mutate in (
            (
                "resolved source hash",
                lambda entry: entry.update(resolvedSourceHash="00" * 32),
            ),
            (
                "validator namespace",
                lambda entry: (
                    entry["attestation"].update(signer=AUTHORITY_REF),
                    entry["sourceAuthority"].update(claim=AUTHORITY_REF),
                ),
            ),
        ):
            with self.subTest(label=label):
                document = copy.deepcopy(self.document)
                entry = next(
                    item for item in document["trustedContext"][
                        "authenticatedSourceAttestations"
                    ]
                    if item["method"] == "consensus-backed-proxy"
                )
                mutate(entry)
                self.assertIsNone(
                    authenticated_result_context(
                        document, authenticated_recipe_registry(document)
                    )
                )

        malformed = copy.deepcopy(vc["artifact"]["attestation"])
        malformed["signer"] = []
        self.assertFalse(well_formed_attestation_ref(malformed))

    def test_identity_bundle_additive_members_are_signed_and_forward_readable(self):
        _, evaluation = self._case_evaluation("vet-ma3-verified-accept")
        changed = copy.deepcopy(evaluation)
        bundle = changed["input"]["bundle"]
        bundle["futureOptional"] = {"version": 2}
        changed["input"]["bundle"] = resign_bundle(
            bundle, fixture_private_key("presenter"),
            public_ref(fixture_private_key("presenter")),
        )
        self.assertTrue(execute_once(changed, self.document))

        unsigned = copy.deepcopy(evaluation)
        unsigned["input"]["bundle"]["futureOptional"] = {"version": 2}
        self.assertFalse(execute_once(unsigned, self.document))

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

    def test_historical_coordinates_are_explicit_and_non_authorizing(self):
        historical = self.document["historicalCompatibilityEvidence"]
        self.assertEqual(4, len(historical))
        self.assertEqual(
            {
                "dacs1-cci-lei-named-matches",
                "vet-oneof-error-over-fail",
                "vet-oneof-indeterminate-over-fail",
                "vet-cross-accumulator-fail-over-error",
            },
            {item["id"] for item in historical},
        )
        for item in historical:
            self.assertEqual("historical-non-authorizing", item["classification"])
            self.assertEqual(
                "42a9a950f2bcd4a4d8ace4d27a6f420212c3ec47",
                item["revision"],
            )
            self.assertEqual(
                "251f2c27f807e0408ce5a7ae0998efef3288e8f5b971d31156e8866219993f3b",
                item["fileSha256"],
            )
            self.assertEqual(
                "conformance/fixtures/identity/dacs1-vet-golden-inputs-v0.1.json",
                item["path"],
            )
        self.assertNotIn(
            "dacs1-cci-lei-named-matches",
            {case["name"] for case in self.cases},
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
                expected = case["expectedOutput"]
                # Aggregate reasons are advisory diagnostics.  The manifest's
                # cross-implementation conformance projection is the decision.
                if isinstance(expected, dict) and set(expected) == {
                    "decision", "reasons"
                }:
                    expected = expected["decision"]
                self.assertEqual(expected, manifest_cases[name]["want"])

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
                    runtime = VetReferenceRuntime(self.document["trustedContext"])
                    admission = runtime.admit(
                        value["authority"], bundle
                    )
                    bundle_ok = verify_bundle(bundle, admission)
                    if case["name"] in {
                        "vet-control-key-malformed-scope-reject-no-throw",
                        "dacs1-cci-lei-current-registry-reject",
                    } and label == "result":
                        self.assertFalse(bundle_ok)
                    else:
                        self.assertTrue(bundle_ok)
                    for resolved in value["resolvedResults"]:
                        self.assertTrue(
                            verify_result(
                                resolved, self.recipes, self.result_context
                            )
                        )

    def test_cci_lei_compatibility_scope_is_explicit_closed_and_discriminating(self):
        case, distinct = self._case_evaluation("dacs1-cci-lei-defect")
        _, current = self._case_evaluation(
            "dacs1-cci-lei-current-registry-reject"
        )
        control = case["evaluations"]["registeredBareLeiControl"]
        context = self.document["trustedContext"]
        profiles = context["deferredSchemeCompatibilityProfiles"]

        distinct_invocation = distinct["input"]["authority"]["invocation"]
        current_invocation = current["input"]["authority"]["invocation"]
        profile_id = context["vetInvocations"][distinct_invocation][
            "compatibilityProfile"
        ]
        self.assertEqual(
            {
                "registeredSchemes": ["cci-lei"],
                "scope": "fixture-only exact-scheme comparison",
            },
            profiles[profile_id],
        )
        self.assertIsNone(
            context["vetInvocations"][current_invocation]["compatibilityProfile"]
        )
        self.assertNotIn(
            "cci-lei",
            {recipe["scheme"] for recipe in context["recipeRegistry"]["recipes"]},
        )

        cci_claim = next(
            item for item in distinct["input"]["bundle"]["claims"]
            if item["ref"].startswith("cci-lei:")
        )
        member = distinct["input"]["requirement"]["required"][0]
        self.assertEqual({"ref"}, set(cci_claim))
        self.assertEqual(
            {"scheme": "lei", "verificationRequired": False}, member
        )
        self.assertNotIn("issuedAt", cci_claim)
        self.assertNotIn("recipeVersion", member)
        self.assertNotIn("maxAge", member)

        runtime = VetReferenceRuntime(context)
        admitted, capability = runtime.admit_synthetic_test_input(distinct)
        admission = runtime.admit(
            admitted["input"]["authority"], admitted["input"]["bundle"]
        )
        self.assertIsNotNone(admission)
        self.assertIn("cci-lei", admission.registered_schemes)
        self.assertEqual(
            ("fail", ["required failing or absent: lei"]),
            evaluate(
                admitted["input"],
                self.recipes,
                self.result_context,
                decision_time=admission.trusted_now,
                admission=admission,
            ),
        )
        self.assertFalse(execute(
            admitted, self.document, runtime, capability
        ))
        self.assertFalse(execute_external_once(
            json.dumps(distinct, separators=(",", ":")).encode("utf-8"),
            self.document,
        ))

        current_runtime = VetReferenceRuntime(context)
        current_admitted, current_capability = (
            current_runtime.admit_synthetic_test_input(current)
        )
        current_admission = current_runtime.admit(
            current_admitted["input"]["authority"],
            current_admitted["input"]["bundle"],
        )
        self.assertIsNotNone(current_admission)
        self.assertEqual(
            ("error", ["invalid identity bundle"]),
            evaluate(
                current_admitted["input"],
                self.recipes,
                self.result_context,
                decision_time=current_admission.trusted_now,
                admission=current_admission,
            ),
        )
        self.assertNotIn("cci-lei", current_admission.registered_schemes)
        self.assertFalse(execute(
            current_admitted, self.document, current_runtime, current_capability
        ))

        # A candidate-carried lookalike cannot select the verifier-owned
        # compatibility profile for the current closed-registry invocation.
        candidate_selected = copy.deepcopy(current)
        candidate_selected["input"]["compatibilityProfile"] = profile_id
        self.assertFalse(execute_once(candidate_selected, self.document))
        candidate_runtime = VetReferenceRuntime(context)
        candidate_admitted, _ = candidate_runtime.admit_synthetic_test_input(
            candidate_selected
        )
        candidate_admission = candidate_runtime.admit(
            candidate_admitted["input"]["authority"],
            candidate_admitted["input"]["bundle"],
        )
        self.assertNotIn("cci-lei", candidate_admission.registered_schemes)

        # Unknown or malformed verifier-owned profile bindings reject before
        # bundle/signature interpretation.
        for label, mutate in (
            (
                "unknown binding",
                lambda document: document["trustedContext"]["vetInvocations"][
                    distinct_invocation
                ].update(compatibilityProfile="unknown-profile"),
            ),
            (
                "malformed profile",
                lambda document: document["trustedContext"][
                    "deferredSchemeCompatibilityProfiles"
                ][profile_id].update(scope="candidate-selectable"),
            ),
            (
                "unhashable binding",
                lambda document: document["trustedContext"]["vetInvocations"][
                    distinct_invocation
                ].update(compatibilityProfile=[]),
            ),
            (
                "missing profile map",
                lambda document: document["trustedContext"].pop(
                    "deferredSchemeCompatibilityProfiles"
                ),
            ),
        ):
            with self.subTest(profile=label):
                document = copy.deepcopy(self.document)
                mutate(document)
                runtime = VetReferenceRuntime(document["trustedContext"])
                with mock.patch(
                    __name__ + ".verify_bundle", wraps=verify_bundle
                ) as bundle_check:
                    self.assertFalse(execute_once(distinct, document))
                bundle_check.assert_not_called()

        # Current-only callers remain compatible with the pre-profile trusted
        # context shape: both the top-level map and per-invocation optional
        # members may be absent when no deferred scheme is requested.
        current_only_document = copy.deepcopy(self.document)
        current_only_context = current_only_document["trustedContext"]
        current_only_context.pop("deferredSchemeCompatibilityProfiles")
        for invocation in current_only_context["vetInvocations"].values():
            invocation.pop("compatibilityProfile", None)
            invocation.pop("compatibilityRequirementHash", None)
        self.assertTrue(execute_once(control, current_only_document))
        self.assertTrue(execute_once(control, self.document))
        self.assertTrue(execute_external_once(
            json.dumps(control, separators=(",", ":")).encode("utf-8"),
            self.document,
        ))

    def test_cci_lei_profile_is_bound_to_its_exact_verifier_requirement(self):
        case, distinct = self._case_evaluation("dacs1-cci-lei-defect")
        control = case["evaluations"]["registeredBareLeiControl"]
        _, current = self._case_evaluation(
            "dacs1-cci-lei-current-registry-reject"
        )
        context = self.document["trustedContext"]
        invocation_id = distinct["input"]["authority"]["invocation"]
        invocation = context["vetInvocations"][invocation_id]
        self.assertEqual(
            hash_hex(distinct["input"]["requirement"]),
            invocation["compatibilityRequirementHash"],
        )
        for other in (control, current):
            other_invocation = context["vetInvocations"][
                other["input"]["authority"]["invocation"]
            ]
            self.assertIsNone(other_invocation["compatibilityProfile"])
            self.assertNotIn("compatibilityRequirementHash", other_invocation)

        # The published comparison, its registered bare-LEI accepting control,
        # and the current-registry refusal keep their outcomes.
        self.assertIs(False, execute_once(distinct, self.document))
        self.assertIs(True, execute_once(control, self.document))
        self.assertIs(False, execute_once(current, self.document))

        # Otherwise-valid one-field negative: nonce, presenter, signed bundle,
        # session, and trusted context are unchanged; only the requirement
        # scheme moves from the bound bare lei to the profile-only cci-lei.
        retargeted = copy.deepcopy(distinct)
        retargeted["input"]["requirement"]["required"][0]["scheme"] = "cci-lei"
        restored = copy.deepcopy(retargeted)
        restored["input"]["requirement"]["required"][0]["scheme"] = "lei"
        self.assertEqual(distinct, restored)
        raw = json.dumps(retargeted, separators=(",", ":")).encode("utf-8")
        self.assertIs(False, execute_external_once(raw, self.document))

        # It reaches the binding guard after SN-4 consumption, with a
        # genuinely bound bundle and a requirement that is well formed under
        # the profile registry.
        runtime = VetReferenceRuntime(context)
        admitted, _ = runtime.admit_synthetic_test_input(retargeted)
        value = admitted["input"]
        admission = runtime.admit(value["authority"], value["bundle"])
        self.assertIsNotNone(admission)
        self.assertTrue(runtime.nonce_ledger.consumed(invocation["challengeId"]))
        self.assertIn("cci-lei", admission.registered_schemes)
        self.assertTrue(verify_bundle(value["bundle"], admission))
        self.assertTrue(
            valid_requirement(value["requirement"], admission.registered_schemes)
        )
        self.assertEqual(
            ("error", ["requirement is not bound to the compatibility profile"]),
            evaluate(
                value,
                self.recipes,
                self.result_context,
                decision_time=admission.trusted_now,
                admission=admission,
            ),
        )
        # The invalid first attempt consumed the issued nonce.
        self.assertIsNone(runtime.admit(
            distinct["input"]["authority"], distinct["input"]["bundle"]
        ))

        # A requirement-free control question cannot reuse the profile, even
        # when the input still carries the bound requirement.
        control_question = copy.deepcopy(distinct)
        control_question["operation"] = "control-decision"
        self.assertEqual("error", execute_once(control_question, self.document))
        current_control_question = copy.deepcopy(control)
        current_control_question["operation"] = "control-decision"
        self.assertEqual(
            "pass", execute_once(current_control_question, self.document)
        )

        # Accepting control: the identical candidate bytes pass only when the
        # verifier-owned invocation itself binds the retargeted requirement.
        rebound = copy.deepcopy(self.document)
        rebound["trustedContext"]["vetInvocations"][invocation_id][
            "compatibilityRequirementHash"
        ] = hash_hex(retargeted["input"]["requirement"])
        self.assertIs(True, execute_external_once(raw, rebound))

        # Missing, malformed, or unpaired verifier-owned bindings reject before
        # bundle interpretation.  The last arm adds a binding to the otherwise
        # accepting current-only control invocation.
        for label, candidate, mutate in (
            (
                "profile without requirement binding",
                retargeted,
                lambda item: item.pop("compatibilityRequirementHash"),
            ),
            (
                "uppercase requirement binding",
                retargeted,
                lambda item: item.update(
                    compatibilityRequirementHash=item[
                        "compatibilityRequirementHash"
                    ].upper()
                ),
            ),
            (
                "non-string requirement binding",
                retargeted,
                lambda item: item.update(compatibilityRequirementHash=[]),
            ),
            (
                "requirement binding without profile",
                control,
                lambda item: item.update(
                    compatibilityRequirementHash=hash_hex(
                        control["input"]["requirement"]
                    )
                ),
            ),
        ):
            with self.subTest(binding=label):
                document = copy.deepcopy(self.document)
                mutate(document["trustedContext"]["vetInvocations"][
                    candidate["input"]["authority"]["invocation"]
                ])
                with mock.patch(
                    __name__ + ".verify_bundle", wraps=verify_bundle
                ) as bundle_check:
                    self.assertIs(False, execute_once(candidate, document))
                bundle_check.assert_not_called()

    def test_stale_primary_selector_reaches_freshness_guard_with_valid_control(self):
        for case_name in (
            "dacs1-freshness-fail-closed",
            "vet-freshness-fail-closed",
        ):
            case = next(item for item in self.cases if item["name"] == case_name)
            stale = case["evaluations"]["stalePresentedByPrimary"]
            control = case["evaluations"]["freshPresentedByPrimaryControl"]
            with self.subTest(case=case_name):
                artifacts = [
                    item["artifact"] for item in stale["input"]["resolvedResults"]
                ]
                self.assertEqual(
                    {("lei", "verifiable-credential", 2)},
                    {
                        (item["scheme"], item["method"], item["recipeVersion"])
                        for item in artifacts
                    },
                )
                self.assertTrue(all(
                    item["data"]["holderBinding"]["controller"]
                    == self.document["publicKeys"]["presenter"]
                    for item in artifacts
                ))
                with mock.patch(
                    __name__ + ".selector_authorized",
                    wraps=selector_authorized,
                ) as selector:
                    self.assertFalse(execute_once(stale, self.document))
                selector.assert_called_once()
                self.assertTrue(execute_once(control, self.document))

    def test_non_key_controlled_donor_cannot_authorize_selected_claim(self):
        _, negative = self._case_evaluation("vet-ma3-unverified-reject")
        donor_case, _ = self._case_evaluation("dacs1-tier-laundering-guard")
        control = donor_case["evaluations"]["selectedPassControl"]
        artifacts = [
            item["artifact"] for item in negative["input"]["resolvedResults"]
        ]
        self.assertEqual(
            {("lei", "verifiable-credential", 2)},
            {
                (item["scheme"], item["method"], item["recipeVersion"])
                for item in artifacts
            },
        )
        self.assertEqual({"fail", "pass"}, {item["decision"] for item in artifacts})
        self.assertTrue(all(
            item["data"]["holderBinding"]["controller"]
            == self.document["publicKeys"]["presenter"]
            for item in artifacts
        ))
        self.assertFalse(execute_once(negative, self.document))
        self.assertTrue(execute_once(control, self.document))

    def test_malformed_scope_fixture_is_authenticated_and_isolates_number_guard(self):
        case, evaluation = self._case_evaluation(
            "vet-control-key-malformed-scope-reject-no-throw"
        )
        bundle = evaluation["input"]["bundle"]
        self.assertIs(True, bundle["presentedAt"])
        unsigned = {key: value for key, value in bundle.items() if key != "presentation"}
        payload = (BUNDLE_DOMAIN + hash_hex(unsigned)).encode("ascii")
        for envelope in bundle["presentation"]["signatures"]:
            Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(envelope["ref"].removeprefix("key:"))
            ).verify(b64url_decode(envelope["signature"]), payload)

        control = copy.deepcopy(evaluation)
        control["input"]["bundle"]["presentedAt"] = 0.5
        presenter = fixture_private_key("presenter")
        control["input"]["bundle"] = resign_bundle(
            control["input"]["bundle"], presenter, public_ref(presenter)
        )
        self.assertEqual({"decision": "pass", "throws": False}, execute_once(control, self.document))
        self.assertEqual({"decision": "error", "throws": False}, case["expectedOutput"])
        self.assertEqual(case["expectedOutput"], execute_once(evaluation, self.document))
        real_safe_number = safe_number
        with mock.patch(
            __name__ + ".safe_number",
            side_effect=lambda value: True if value is True else real_safe_number(value),
        ):
            self.assertEqual(
                {"decision": "pass", "throws": False},
                execute_once(evaluation, self.document),
            )

    def test_recipe_registry_is_signed_closed_and_family_qualified(self):
        self.assertIsNotNone(self.recipes)
        self.assertEqual(6, len(self.recipes))
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
        # A genuinely signed result authenticates only for a (scheme, method,
        # recipeVersion) execution that the signed recipe registry supports.
        # Every other prerequisite is granted for the substituted family -- the
        # trusted full-artifact hash, a result authority for that exact family
        # and a family-matched source attestation -- so only the registry's
        # method/version support can reject.  The registered tlsnotary
        # alternative, built the same way, is the accepted control.
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        resolved = evaluation["input"]["resolvedResults"][0]
        artifact = resolved["artifact"]
        self.assertEqual(
            ("lei", "consensus-backed-proxy", 1),
            (artifact["scheme"], artifact["method"], artifact["recipeVersion"]),
        )
        self.assertIs(True, verify_result(resolved, self.recipes, self.result_context))
        attestation_key = canonical_bytes(artifact["attestation"])

        def substituted(method, version):
            source = copy.deepcopy(resolved)
            source["artifact"].update(method=method, recipeVersion=version)
            changed = resign_result(
                source, fixture_private_key("authority"), AUTHORITY_REF
            )
            trust = copy.deepcopy(self.result_context)
            trust["resultHashByRef"][canonical_bytes(changed["ref"])] = changed[
                "serializedArtifactHash"
            ]
            trust["authorityByFamily"].setdefault(("lei", method, version), {
                "scheme": "lei", "method": method, "recipeVersion": version,
                "algorithm": "ed25519", "signer": AUTHORITY_REF,
            })
            trust["attestationByKey"][attestation_key] = {
                **trust["attestationByKey"][attestation_key],
                "method": method,
                "recipeVersion": version,
            }
            return changed, trust

        changed, trust = substituted("tlsnotary", 1)
        self.assertIs(True, verify_result(changed, self.recipes, trust))
        for method, version in (
            ("vc-presentation", 1),        # unknown method kind
            ("zktls", 1),                  # known kind that no lei recipe supports
            ("verifiable-credential", 1),  # owner family exists only at version 2
            ("tlsnotary", 2),              # alternative registered only at version 1
        ):
            with self.subTest(method=method, recipeVersion=version):
                changed, trust = substituted(method, version)
                self.assertIs(False, verify_result(changed, self.recipes, trust))

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
            if item["name"] == "vet-ma3-verified-accept"
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
        admitted, input_capability = execution_runtime.admit_synthetic_test_input(
            case["evaluations"]["result"]
        )
        self.assertTrue(execute(
            admitted, self.document, execution_runtime, input_capability
        ))
        self.assertFalse(execute(
            admitted, self.document, execution_runtime, input_capability
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

    def test_aggregate_presentations_use_distinct_challenges_and_capabilities(self):
        case = next(
            item for item in self.cases
            if item["name"] == "vet-oneof-error-over-fail"
        )
        evaluation = case["evaluations"]["result"]
        value = evaluation["input"]
        authority = value["authority"]
        vet_input = authority["vetInput"]
        invocation = self.document["trustedContext"]["vetInvocations"][
            authority["invocation"]
        ]
        bundle_challenge = invocation["challengeId"]
        verifier_challenge = invocation["verifierIdentityChallengeId"]
        issuances = {
            item["challengeId"]: item
            for item in self.document["trustedContext"]["nonceIssuances"]
        }
        self.assertNotEqual(bundle_challenge, verifier_challenge)
        self.assertNotEqual(
            issuances[bundle_challenge]["nonce"],
            issuances[verifier_challenge]["nonce"],
        )
        self.assertEqual(
            vet_input["bundleToVet"]["presentedBy"],
            issuances[bundle_challenge]["evaluatedParty"],
        )
        self.assertEqual(
            vet_input["verifierIdentity"]["presentedBy"],
            issuances[verifier_challenge]["evaluatedParty"],
        )
        self.assertEqual(
            invocation["phaseOrchestrator"],
            issuances[verifier_challenge]["issuedBy"],
        )

        runtime = VetReferenceRuntime(self.document["trustedContext"])
        bundle_admission = runtime.admit(authority, vet_input["bundleToVet"])
        verifier_admission = runtime.admit_verifier_identity(
            authority, vet_input["verifierIdentity"]
        )
        self.assertIsNotNone(bundle_admission)
        self.assertIsNotNone(verifier_admission)
        self.assertTrue(runtime.nonce_ledger.consumed(bundle_challenge))
        self.assertTrue(runtime.nonce_ledger.consumed(verifier_challenge))
        # Nested validation may recheck one accepted presentation through its
        # own capability without attempting another ledger consumption.
        self.assertTrue(verify_bundle(vet_input["bundleToVet"], bundle_admission))
        self.assertTrue(verify_bundle(vet_input["bundleToVet"], bundle_admission))
        self.assertTrue(verify_bundle(
            vet_input["verifierIdentity"], verifier_admission
        ))
        self.assertTrue(verify_bundle(
            vet_input["verifierIdentity"], verifier_admission
        ))
        changed_identity = copy.deepcopy(vet_input["verifierIdentity"])
        changed_identity["presentedAt"] -= 1
        changed_identity = resign_bundle(
            changed_identity,
            fixture_private_key("verifier"),
            public_ref(fixture_private_key("verifier")),
        )
        self.assertFalse(verify_bundle(changed_identity, verifier_admission))
        self.assertFalse(verify_bundle(
            vet_input["verifierIdentity"], bundle_admission
        ))
        self.assertFalse(verify_bundle(
            vet_input["bundleToVet"], verifier_admission
        ))

        wrong_bundle = copy.deepcopy(evaluation)
        wrong_vet_input = wrong_bundle["input"]["authority"]["vetInput"]
        wrong_vet_input["bundleToVet"]["sessionNonce"] = "00" * 16
        runtime = VetReferenceRuntime(self.document["trustedContext"])
        self.assertIsNone(runtime.admit(
            wrong_bundle["input"]["authority"], wrong_vet_input["bundleToVet"]
        ))
        self.assertIsNotNone(runtime.admit_verifier_identity(
            wrong_bundle["input"]["authority"], wrong_vet_input["verifierIdentity"]
        ))
        self.assertFalse(runtime.nonce_ledger.consumed(bundle_challenge))
        self.assertTrue(runtime.nonce_ledger.consumed(verifier_challenge))

        reused = copy.deepcopy(evaluation)
        reused_vet_input = reused["input"]["authority"]["vetInput"]
        reused_identity = reused_vet_input["verifierIdentity"]
        reused_identity["sessionNonce"] = reused_vet_input["bundleToVet"][
            "sessionNonce"
        ]
        reused_vet_input["verifierIdentity"] = resign_bundle(
            reused_identity,
            fixture_private_key("verifier"),
            public_ref(fixture_private_key("verifier")),
        )
        runtime = VetReferenceRuntime(self.document["trustedContext"])
        bundle_admission = runtime.admit(
            reused["input"]["authority"], reused_vet_input["bundleToVet"]
        )
        self.assertIsNotNone(bundle_admission)
        self.assertIsNone(runtime.admit_verifier_identity(
            reused["input"]["authority"], reused_vet_input["verifierIdentity"]
        ))
        self.assertTrue(runtime.nonce_ledger.consumed(bundle_challenge))
        self.assertFalse(runtime.nonce_ledger.consumed(verifier_challenge))
        self.assertFalse(verify_bundle(
            reused_vet_input["verifierIdentity"], bundle_admission
        ))
        self.assertEqual(
            {"decision": "error", "reasons": ["aggregation authority invalid"]},
            execute_once(reused, self.document),
        )

    def test_invocation_context_authenticates_phase_actor_and_authorities(self):
        case = next(
            item for item in self.cases
            if item["name"] == "vet-ma3-verified-accept"
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
        verifier_identity_admission = runtime.admit_verifier_identity(
            evaluation["input"]["authority"],
            evaluation["input"]["authority"]["vetInput"]["verifierIdentity"],
        )
        projection = authenticate_production_aggregate(
            evaluation["input"],
            self.document["trustedContext"],
            self.recipes,
            self.result_context,
            admission,
            verifier_identity_admission,
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

        # Every mutation is re-signed AND re-anchored: without moving the
        # trusted receipt, the old receipt content hash alone would reject it
        # and the signal checks would be untested.
        generated_at = record["generatedAt"]

        def replay(mutate):
            document = copy.deepcopy(self.document)
            changed = copy.deepcopy(evaluation)
            mutate(changed["input"]["record"]["supplementary"])
            changed["input"] = reanchor_composite_input(changed["input"], document)
            return execute_once(changed, document)

        # Control: a different but valid signal keeps the golden output.
        self.assertEqual(
            case["expectedOutput"],
            replay(lambda signals: signals[0].update(observedAt=generated_at)),
        )
        for label, mutate in (
            ("negative observedAt", lambda s: s[0].update(observedAt=-1)),
            ("observedAt after generatedAt",
             lambda s: s[0].update(observedAt=generated_at + 1)),
            ("missing signalType", lambda s: s[0].pop("signalType")),
            ("external without attestation",
             lambda s: (s[0].update(source="external"), s[0].pop("attestation", None))),
            ("boolean value", lambda s: s[0].update(value=True)),
            ("non-object element", lambda s: s.clear() or s.append("not-a-signal")),
        ):
            with self.subTest(label=label):
                self.assertEqual(
                    {"decision": "error", "reasons": ["aggregation authority invalid"]},
                    replay(mutate),
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

        for malformed in (None, 1, True, [], {}):
            with self.subTest(malformed=malformed):
                bundle = copy.deepcopy(value["bundle"])
                bundle["presentation"]["signatures"][0]["ref"] = malformed
                self.assertFalse(verify_bundle(bundle, admission))
                # Without an admission the changed presentation bytes cannot
                # reject first, so the signature-reference type check decides.
                self.assertIs(False, verify_bundle(bundle))

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
                        resolved["artifact"][field] = (
                            0 if field == "recipeVersion" and malformed == 1
                            and type(malformed) is int else malformed
                        )
                        self.assertFalse(verify_result(
                            resolved, self.recipes, self.result_context
                        ))
                resolved = copy.deepcopy(value["resolvedResults"][0])
                resolved["artifact"]["signature"]["signer"] = malformed
                self.assertFalse(verify_result(
                    resolved, self.recipes, self.result_context
                ))

    def test_present_non_string_primary_selector_is_invalid_not_absent(self):
        direct = next(
            item for item in self.cases
            if item["name"] == "vet-control-existence-only-lei-supporting-context"
        )["evaluations"]["result"]
        aggregate_case, aggregate = self._case_evaluation(
            "vet-oneof-indeterminate-over-fail"
        )
        self.assertEqual(
            aggregate_case["expectedOutput"],
            execute_once(aggregate, self.document),
        )
        for malformed in (None, [], {}):
            with self.subTest(path="direct", malformed=malformed):
                changed = copy.deepcopy(direct)
                changed["input"]["requirement"]["primaryClaimSelector"] = malformed
                self.assertFalse(valid_requirement(changed["input"]["requirement"]))
                self.assertEqual("error", execute_once(changed, self.document))
            with self.subTest(path="aggregate", malformed=malformed):
                document = copy.deepcopy(self.document)
                changed = copy.deepcopy(aggregate)
                requirement = changed["input"]["authority"]["vetInput"][
                    "requirement"
                ]
                requirement["primaryClaimSelector"] = malformed
                changed["input"]["record"]["requirementHash"] = hash_hex(
                    requirement
                )
                changed["input"]["record"]["overallDecision"] = "error"
                changed["input"] = reanchor_composite_input(
                    changed["input"], document
                )
                self.assertEqual(
                    {"decision": "error", "reasons": [
                        "invalid bundle requirement"
                    ]},
                    execute_once(changed, document),
                )

    def test_preferred_presentation_uses_its_closed_enum(self):
        direct_case, direct = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        aggregate_case, aggregate = self._case_evaluation(
            "vet-oneof-indeterminate-over-fail"
        )
        self.assertEqual(
            aggregate_case["expectedOutput"],
            execute_once(aggregate, self.document),
        )
        for value in ("siwd", "sr1-root", "per-claim", "session-key", "any"):
            with self.subTest(value=value):
                changed = copy.deepcopy(direct)
                changed["input"]["requirement"]["preferredPresentation"] = value
                self.assertTrue(valid_requirement(changed["input"]["requirement"]))
                self.assertEqual(
                    direct_case["expectedOutput"], execute_once(changed, self.document)
                )
        for malformed in (None, "", "unknown", 1, True, [], {}):
            with self.subTest(path="direct", malformed=malformed):
                changed = copy.deepcopy(direct)
                changed["input"]["requirement"]["preferredPresentation"] = malformed
                self.assertEqual("error", execute_once(changed, self.document))
            with self.subTest(path="aggregate", malformed=malformed):
                document = copy.deepcopy(self.document)
                changed = copy.deepcopy(aggregate)
                requirement = changed["input"]["authority"]["vetInput"][
                    "requirement"
                ]
                requirement["preferredPresentation"] = malformed
                changed["input"]["record"]["requirementHash"] = hash_hex(requirement)
                changed["input"]["record"]["overallDecision"] = "error"
                changed["input"] = reanchor_composite_input(
                    changed["input"], document
                )
                self.assertEqual(
                    {"decision": "error", "reasons": [
                        "invalid bundle requirement"
                    ]},
                    execute_once(changed, document),
                )

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
                verifier_identity_admission = runtime.admit_verifier_identity(
                    changed["authority"],
                    changed["authority"]["vetInput"]["verifierIdentity"],
                )
                self.assertIsNotNone(verifier_identity_admission)
                self.assertIsNone(authenticate_production_aggregate(
                    changed, self.document["trustedContext"], self.recipes,
                    self.result_context, admission, verifier_identity_admission,
                    runtime,
                ))
                self.assertEqual(
                    {"decision": "error", "reasons": ["aggregation authority invalid"]},
                    execute_once(
                        {"operation": "aggregate", "input": changed}, self.document
                    ),
                )

    def test_max_age_must_be_a_nonnegative_finite_safe_number(self):
        case = next(
            item for item in self.cases
            if item["name"]
            == "vet-control-existence-only-lei-supporting-context"
        )
        evaluation = case["evaluations"]["result"]
        for max_age in ("60", -1, SAFE_INT + 1, True, float("nan"), float("inf")):
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
            if item["name"] == "vet-ma3-verified-accept"
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
        # DACS-1 §6.3.2 step (6): only a verifiable-credential holder binding to
        # a presentation signer proves control of a non-key presentedBy claim.
        # Each variant is re-signed by the genuine result authority with its
        # full-artifact hash, provenance and source family registered, and the
        # bundle is re-pointed and re-signed, so the result authenticates and
        # only the substituted method or data can decide control.
        _, evaluation = self._case_evaluation("vet-ma3-verified-accept")
        uncontrolled = (
            "fail",
            ["primaryClaimSelector is mismatched, uncontrolled, or unauthorized"],
        )

        def resigned(**fields):
            return lambda artifact: artifact.update(
                reason="re-signed substitution", **fields
            )

        def outcomes(source, mutate_artifact, *, authenticates=True):
            document = copy.deepcopy(self.document)
            changed = rebuild_direct_result(source, document, mutate_artifact)
            resolved = changed["input"]["resolvedResults"][0]
            if authenticates:
                set_result_attestation_family(document, resolved)
            recipes = authenticated_recipe_registry(document)
            self.assertIs(authenticates, verify_result(
                resolved, recipes, authenticated_result_context(document, recipes)
            ))
            control = copy.deepcopy(changed)
            control["operation"] = "control-decision"
            return (
                self._direct_outcome(changed, document),
                execute_once(control, document),
            )

        # Control: the unchanged credential re-signed through the same path.
        self.assertEqual((("pass", []), "pass"), outcomes(evaluation, resigned()))
        method_source = copy.deepcopy(evaluation)
        method_source["input"]["requirement"]["required"][0]["recipeVersion"] = 1
        for label, source, mutate in (
            ("holder binding names a non-signer", evaluation, resigned(data={
                "holderBinding": {
                    "controller": public_ref(fixture_private_key("replacement-signer")),
                },
            })),
            ("holder binding removed", evaluation, resigned(data={})),
            ("registered non-credential method keeps the binding", method_source,
             resigned(method="tlsnotary", recipeVersion=1)),
        ):
            with self.subTest(label=label):
                self.assertEqual((uncontrolled, "fail"), outcomes(source, mutate))

        # An existence-only result re-signed as a credential at a version whose
        # recipe has no credential method is refused at authentication (that
        # family guard is isolated by the unregistered-family test above).
        _, forged = self._case_evaluation(
            "vet-control-existence-method-forged-holderbinding-reject"
        )
        self.assertEqual(
            (uncontrolled, "fail"),
            outcomes(forged, resigned(method="verifiable-credential"),
                     authenticates=False),
        )

    def test_vpc4_terminal_fault_attribution_is_derived(self):
        self.assertEqual("counterparty", vpc4_error_class("fail"))
        self.assertEqual("permanent", vpc4_error_class("error"))
        self.assertEqual("permanent", vpc4_error_class("indeterminate"))
        self.assertEqual(
            "counterparty",
            vpc4_error_class("error", counterparty_malformed=True),
        )
        self.assertNotEqual("transient", vpc4_error_class("error"))

    def test_vet_corrective_declaration_names_the_current_profile_tuple(self):
        # The Vet correction joins the existing unreleased candidate without a
        # version bump, so every restatement must name the PROFILE table's
        # current labels; a stale tuple in any one document fails here.
        def text(path):
            return " ".join((ROOT / path).read_text(encoding="utf-8").split())

        profile = (ROOT / "spec" / "PROFILE.md").read_text(encoding="utf-8")
        section = profile.split("\n## Unreleased corrective candidate\n", 1)[1]
        section = section.split("\n## ", 1)[0]
        table = dict(re.findall(
            r"\| \[(CORE|DACS-[1-5])[^\]]*\]\([^)]*\) \| (\d+\.\d+) \|", section
        ))
        self.assertEqual(
            {"CORE", "DACS-1", "DACS-2", "DACS-3", "DACS-4", "DACS-5"}, set(table)
        )
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            {key.lower().replace("-", ""): value for key, value in table.items()},
            manifest["syntheticProfileAdmissionFixture"]["moduleVersions"],
        )
        core, d1, d2 = table["CORE"], table["DACS-1"], table["DACS-2"]
        vet_labels = f"CORE v{core}, DACS-1 v{d1}, and DACS-2 v{d2}"
        core_text = text("spec/CORE.md")
        self.assertIn(f"**DACS Core v{core}**", core_text)
        tuple_text = (
            f"CORE v{core} together with DACS-1 v{d1}, DACS-2 v{d2}, "
            f"DACS-3 v{table['DACS-3']}, DACS-4 v{table['DACS-4']}, and "
            f"DACS-5 v{table['DACS-5']}"
        )
        self.assertIn(
            f"The unreleased coordinated corrective candidate is {tuple_text}.",
            core_text,
        )
        self.assertIn(
            f"for Vet, {vet_labels} change existing execution behaviour",
            core_text,
        )
        self.assertIn(
            "This candidate is a **breaking pre-v1 correction** under CORE "
            "§11.1.2",
            " ".join(section.split()),
        )
        for name, version, affected in (
            ("CORE", core, "shared Vet admission behaviour affected"),
            (
                "DACS-1",
                d1,
                "session presentation, and current composed module behaviour affected",
            ),
            ("DACS-2", d2, "Vet aggregation and authority behaviour affected"),
        ):
            with self.subTest(row=name):
                row = next(
                    line for line in section.splitlines()
                    if line.startswith(f"| [{name}")
                )
                self.assertIn(f"| {version} |", row)
                self.assertIn(affected, row)
        self.assertIn(
            f"**DACS-1 v{d1}** on the common DACS v0.1 baseline", text("spec/DACS-1-IDENTIFY.md")
        )
        self.assertIn(
            "v0.7 participates in the declared CORE §11.1.2 breaking pre-v1 "
            "corrective boundary",
            text("spec/DACS-1-IDENTIFY.md"),
        )
        dacs2 = text("spec/DACS-2-VET.md")
        self.assertIn(f"**DACS-2 v{d2}**", dacs2)
        self.assertIn(
            f"v{d2} is an affected document in the declared CORE §11.1.2 "
            "**breaking pre-v1 corrective candidate**",
            dacs2,
        )
        heading = next(
            line for line in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()
            if line.startswith("### Breaking pre-v1 correction — Vet admission")
        )
        self.assertTrue(
            heading.endswith(f"(CORE v{core} / DACS-1 v{d1} / DACS-2 v{d2})"), heading
        )
        # Every other label-bearing restatement of the same declaration.
        for path, phrase in (
            ("CHANGELOG.md",
             f"The current complete tuple is CORE v{core} / DACS-1 v{d1} / "
             f"DACS-2 v{d2} / DACS-3 v{table['DACS-3']} / "
             f"DACS-4 v{table['DACS-4']} / DACS-5 v{table['DACS-5']}."),
            ("spec/CORE.md",
             f"a pre-correction implementation carrying the same v{core} label "
             "is not presumed interoperable"),
            ("spec/DACS-1-IDENTIFY.md",
             "the version label alone does not establish interoperability with "
             "pre-correction behavior"),
            ("spec/DACS-2-VET.md",
             f"the v{d2} label alone does not establish interoperability with "
             f"pre-correction v{d2} execution behavior"),
        ):
            with self.subTest(path=path):
                self.assertIn(phrase, text(path))

    # -- Review/repair regressions: each negative has a positive control. --

    def _case_evaluation(self, name, label="result"):
        case = next(item for item in self.cases if item["name"] == name)
        return case, case["evaluations"][label]

    def test_current_non_pass_results_replay_with_exact_production_provenance(self):
        observed = set()
        for case in self.cases:
            evaluation = case["evaluations"].get("result")
            if evaluation is None or evaluation["operation"] != "aggregate":
                continue
            observed.update(
                result["artifact"]["decision"]
                for result in evaluation["input"]["resolvedResults"]
                if result["artifact"]["decision"] != "pass"
            )
            self.assertEqual(
                case["expectedOutput"], execute_once(evaluation, self.document)
            )
        self.assertEqual({"fail", "error", "indeterminate"}, observed)

    def test_active_aggregate_time_is_bound_to_both_challenges_and_currentness(self):
        case, evaluation = self._case_evaluation(
            "vet-oneof-indeterminate-over-fail"
        )
        self.assertEqual(case["expectedOutput"], execute_once(evaluation, self.document))
        invocation_id = evaluation["input"]["authority"]["invocation"]
        generated_at = evaluation["input"]["record"]["generatedAt"]
        invocation = self.document["trustedContext"]["vetInvocations"][invocation_id]
        challenge_ids = (
            invocation["challengeId"], invocation["verifierIdentityChallengeId"]
        )

        for challenge_id in challenge_ids:
            with self.subTest(challenge=challenge_id):
                document = copy.deepcopy(self.document)
                issuance = next(
                    item for item in document["trustedContext"]["nonceIssuances"]
                    if item["challengeId"] == challenge_id
                )
                issuance["issuedAt"] = generated_at + 1
                self.assertEqual(
                    "error", execute_once(evaluation, document)["decision"]
                )
                self.assertEqual(
                    case["expectedOutput"],
                    reconstruct_historical_once(evaluation, document),
                )

        equality = copy.deepcopy(self.document)
        for issuance in equality["trustedContext"]["nonceIssuances"]:
            if issuance["challengeId"] in challenge_ids:
                issuance["issuedAt"] = generated_at
        self.assertEqual(case["expectedOutput"], execute_once(evaluation, equality))

        late = copy.deepcopy(self.document)
        late_context = late["trustedContext"]["vetInvocations"][invocation_id]
        late_context["trustedNow"] = generated_at + 61_000
        for issuance in late["trustedContext"]["nonceIssuances"]:
            if issuance["challengeId"] in challenge_ids:
                issuance["expiresAt"] = generated_at + 120_000
        self.assertEqual("error", execute_once(evaluation, late)["decision"])
        self.assertEqual(
            case["expectedOutput"], reconstruct_historical_once(evaluation, late)
        )

    def test_cached_non_pass_requires_equal_complete_origin_parameters(self):
        _, evaluation = self._case_evaluation(
            "vet-oneof-indeterminate-over-fail"
        )

        # A verifier-authenticated cache origin with the same absent parameter
        # representation is eligible for each non-pass result.
        control_document = copy.deepcopy(self.document)
        control = copy.deepcopy(evaluation)
        for resolved in control["input"]["resolvedResults"]:
            set_result_provenance(
                control_document, resolved,
                cached=[{"parametersPresence": "absent"}],
            )
        self.assertEqual(
            {"decision": "indeterminate", "reasons": [
                "oneOf group: at least one claim indeterminate"
            ]},
            execute_once(control, control_document),
        )

        # Explicitly present empty parameters are not the same origin as
        # absent parameters, in either direction.
        for current_parameters, cached_origin in (
            ({}, {"parametersPresence": "absent"}),
            (None, {"parametersPresence": "present", "parameters": {}}),
        ):
            with self.subTest(
                current_parameters=current_parameters,
                cached_origin=cached_origin,
            ):
                document = copy.deepcopy(self.document)
                candidate = copy.deepcopy(evaluation)
                requirement = candidate["input"]["authority"]["vetInput"][
                    "requirement"
                ]
                domain = next(
                    item for item in requirement["oneOf"][0]
                    if item["scheme"] == "domain"
                )
                if current_parameters is not None:
                    domain["parameters"] = current_parameters
                for resolved in candidate["input"]["resolvedResults"]:
                    origin = (
                        cached_origin
                        if resolved["artifact"]["scheme"] == "domain"
                        else {"parametersPresence": "absent"}
                    )
                    set_result_provenance(document, resolved, cached=[origin])
                candidate["input"]["record"]["requirementHash"] = hash_hex(
                    requirement
                )
                candidate["input"]["record"]["overallDecision"] = "indeterminate"
                candidate["input"] = reanchor_composite_input(
                    candidate["input"], document
                )
                self.assertEqual(
                    {"decision": "error", "reasons": [
                        "signed overallDecision does not match replay"
                    ]},
                    execute_once(candidate, document),
                )

        # The same signed non-pass cannot be relabelled for a new predicate.
        changed_document = copy.deepcopy(self.document)
        changed = copy.deepcopy(evaluation)
        requirement = changed["input"]["authority"]["vetInput"]["requirement"]
        domain = next(
            item for item in requirement["oneOf"][0]
            if item["scheme"] == "domain"
        )
        domain["parameters"] = {"jurisdiction": "GB"}
        for resolved in changed["input"]["resolvedResults"]:
            set_result_provenance(
                changed_document, resolved,
                cached=[{"parametersPresence": "absent"}],
            )
        changed["input"]["record"]["requirementHash"] = hash_hex(requirement)
        changed["input"]["record"]["overallDecision"] = "indeterminate"
        # Candidate labels are deliberately ignored as provenance.
        changed["input"]["originatingParametersAuthenticated"] = True
        changed["input"]["currentResult"] = True
        changed["input"] = reanchor_composite_input(
            changed["input"], changed_document
        )
        self.assertEqual(
            {"decision": "error", "reasons": [
                "signed overallDecision does not match replay"
            ]},
            execute_once(changed, changed_document),
        )

    def test_current_non_pass_cannot_cross_requirement_predicates(self):
        _, evaluation = self._case_evaluation(
            "vet-oneof-indeterminate-over-fail"
        )
        document = copy.deepcopy(self.document)
        changed = copy.deepcopy(evaluation)
        requirement = changed["input"]["authority"]["vetInput"]["requirement"]
        domain = next(
            item for item in requirement["oneOf"][0]
            if item["scheme"] == "domain"
        )
        domain["parameters"] = {"jurisdiction": "GB"}
        # Leave the original verifier-owned current-production entries intact:
        # they bind the old whole requirement/member hashes and cannot be
        # relabelled as output of this admitted invocation under the new bytes.
        changed["input"]["record"]["requirementHash"] = hash_hex(requirement)
        changed["input"]["record"]["overallDecision"] = "indeterminate"
        changed["input"] = reanchor_composite_input(changed["input"], document)
        self.assertEqual(
            {"decision": "error", "reasons": [
                "signed overallDecision does not match replay"
            ]},
            execute_once(changed, document),
        )

    def test_exact_owned_non_pass_preflight_cannot_be_masked(self):
        _, one_of = self._case_evaluation("vet-oneof-indeterminate-over-fail")
        document = copy.deepcopy(self.document)
        changed = rebuild_aggregate_result(
            one_of, document,
            lambda artifact: artifact.update(decision="pass"),
            index=0, overall_decision="pass",
        )
        domain = changed["input"]["resolvedResults"][1]
        set_result_provenance(
            document, domain,
            cached=[{"parametersPresence": "present", "parameters": {}}],
        )
        self.assertEqual(
            {"decision": "error", "reasons": [
                "signed overallDecision does not match replay"
            ]},
            execute_once(changed, document),
        )

        _, required = self._case_evaluation(
            "vet-cross-accumulator-fail-over-error"
        )
        document = copy.deepcopy(self.document)
        changed = copy.deepcopy(required)
        lei = next(
            item for item in changed["input"]["resolvedResults"]
            if item["artifact"]["scheme"] == "lei"
        )
        set_result_provenance(
            document, lei,
            cached=[{"parametersPresence": "present", "parameters": {}}],
        )
        changed["input"]["record"]["overallDecision"] = "fail"
        changed["input"] = reanchor_composite_input(changed["input"], document)
        self.assertEqual(
            {"decision": "error", "reasons": [
                "signed overallDecision does not match replay"
            ]},
            execute_once(changed, document),
        )

    def test_missing_duplicate_or_mismatched_result_provenance_is_rejected(self):
        _, evaluation = self._case_evaluation(
            "vet-oneof-indeterminate-over-fail"
        )
        domain_result = evaluation["input"]["resolvedResults"][1]
        for label, mutate, expected_reason in (
            (
                "missing",
                lambda provenance, entry: provenance.remove(entry),
                "unresolved recipe family or version",
            ),
            (
                "duplicate",
                lambda provenance, entry: provenance.append(copy.deepcopy(entry)),
                "aggregation authority invalid",
            ),
            (
                "artifact hash mismatch",
                lambda provenance, entry: entry.update(
                    serializedArtifactHash="0" * 64
                ),
                "aggregation authority invalid",
            ),
            (
                "reference mismatch",
                lambda provenance, entry: entry["ref"].update(
                    contentHash="0" * 64
                ),
                "aggregation authority invalid",
            ),
        ):
            with self.subTest(label=label):
                document = copy.deepcopy(self.document)
                changed = copy.deepcopy(evaluation)
                provenance = document["trustedContext"][
                    "authenticatedResultProvenance"
                ]
                entry = result_provenance_entry(document, domain_result)
                mutate(provenance, entry)
                changed["input"]["record"]["overallDecision"] = "error"
                changed["input"] = reanchor_composite_input(
                    changed["input"], document
                )
                observed = execute_once(changed, document)
                self.assertEqual(
                    {"decision": "error", "reasons": [expected_reason]},
                    observed,
                )

    def test_current_rerun_replaces_the_committed_non_pass_reference(self):
        _, evaluation = self._case_evaluation(
            "vet-oneof-indeterminate-over-fail"
        )
        document = copy.deepcopy(self.document)
        changed = copy.deepcopy(evaluation)
        requirement = changed["input"]["authority"]["vetInput"]["requirement"]
        domain = next(
            item for item in requirement["oneOf"][0]
            if item["scheme"] == "domain"
        )
        domain["parameters"] = {"jurisdiction": "GB"}
        # The unchanged LEI failure is an eligible equal-predicate cache hit.
        set_result_provenance(
            document, changed["input"]["resolvedResults"][0],
            cached=[{"parametersPresence": "absent"}],
        )
        old_domain_ref = copy.deepcopy(
            changed["input"]["resolvedResults"][1]["ref"]
        )
        changed = rebuild_aggregate_result(
            changed,
            document,
            lambda artifact: artifact.update(
                reason="current rerun for jurisdiction GB"
            ),
            index=1,
            overall_decision="indeterminate",
        )
        new_domain = changed["input"]["resolvedResults"][1]
        self.assertNotEqual(old_domain_ref, new_domain["ref"])
        self.assertNotIn(old_domain_ref, changed["input"]["record"]["dealSpecific"])
        self.assertIn(new_domain["ref"], changed["input"]["record"]["dealSpecific"])
        self.assertEqual(
            {"decision": "indeterminate", "reasons": [
                "oneOf group: at least one claim indeterminate"
            ]},
            execute_once(changed, document),
        )

    def test_cached_pass_still_requires_current_parameter_data(self):
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        parameters = {
            "verificationMethod": "consensus-backed-proxy",
            "jurisdiction": "GB",
        }
        for jurisdiction, expected in (("GB", "pass"), ("US", "fail")):
            with self.subTest(jurisdiction=jurisdiction):
                document = copy.deepcopy(self.document)
                source = copy.deepcopy(evaluation)
                source["input"]["requirement"]["required"][0][
                    "parameters"
                ] = copy.deepcopy(parameters)
                changed = rebuild_direct_result(
                    source,
                    document,
                    lambda artifact, jurisdiction=jurisdiction: artifact.update(
                        data={"jurisdiction": jurisdiction}
                    ),
                )
                set_result_provenance(
                    document,
                    changed["input"]["resolvedResults"][0],
                    cached=[{
                        "parametersPresence": "present",
                        "parameters": copy.deepcopy(parameters),
                    }],
                )
                self.assertEqual(expected, execute_once(changed, document))

    def test_signed_alternative_method_resolves_explicitly_and_implicitly(self):
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        self.assertEqual("pass", execute_once(evaluation, self.document))
        for explicit in (True, False):
            with self.subTest(explicit=explicit):
                document = copy.deepcopy(self.document)
                source = copy.deepcopy(evaluation)
                member = source["input"]["requirement"]["required"][0]
                member["parameters"] = {"verificationMethod": "tlsnotary"}
                if not explicit:
                    member.pop("recipeVersion")
                changed = rebuild_direct_result(
                    source,
                    document,
                    lambda artifact: artifact.update(method="tlsnotary"),
                )
                set_result_attestation_family(
                    document, changed["input"]["resolvedResults"][0]
                )
                self.assertEqual("pass", execute_once(changed, document))

    def test_alternative_method_uses_owner_authority_and_max_age(self):
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        now = self.document["trustedContext"]["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]["trustedNow"]
        owner = self.recipes[("lei", "consensus-backed-proxy", 1)]
        for age, expected in (
            (owner["defaultMaxAgeSec"] * 1_000, "pass"),
            (owner["defaultMaxAgeSec"] * 1_000 + 1, "fail"),
        ):
            with self.subTest(age=age):
                document = copy.deepcopy(self.document)
                source = copy.deepcopy(evaluation)
                source["input"]["requirement"]["required"][0][
                    "parameters"
                ] = {"verificationMethod": "tlsnotary"}
                changed = rebuild_direct_result(
                    source,
                    document,
                    lambda artifact, age=age: (
                        artifact.update(
                            method="tlsnotary",
                            fetchedAt=now - age,
                            verifiedAt=now - age,
                        ),
                        artifact.pop("validUntil"),
                    ),
                )
                set_result_attestation_family(
                    document, changed["input"]["resolvedResults"][0]
                )
                self.assertEqual(expected, execute_once(changed, document))

    def test_alternative_recipe_ownership_is_closed_signed_and_unambiguous(self):
        base_document = copy.deepcopy(self.document)
        recipes = base_document["trustedContext"]["recipeRegistry"]["recipes"]
        mutations = []

        unsigned = copy.deepcopy(base_document)
        next(
            recipe for recipe in unsigned["trustedContext"]["recipeRegistry"]["recipes"]
            if recipe["scheme"] == "lei" and recipe["recipeVersion"] == 1
        )["alternatives"][0]["endpoint"] += "?unsigned=true"
        mutations.append(("unsigned", unsigned))

        unregistered = copy.deepcopy(base_document)
        recipe = next(
            item for item in unregistered["trustedContext"]["recipeRegistry"]["recipes"]
            if item["scheme"] == "lei" and item["recipeVersion"] == 1
        )
        recipe["alternatives"].append({"kind": "vc-presentation"})
        resign_recipe(recipe)
        mutations.append(("unregistered", unregistered))

        ambiguous = copy.deepcopy(base_document)
        recipe = next(
            item for item in ambiguous["trustedContext"]["recipeRegistry"]["recipes"]
            if item["scheme"] == "lei" and item["recipeVersion"] == 2
        )
        recipe["alternatives"] = [{
            "kind": "tlsnotary",
            "endpoint": "https://vc.example/lei/{identifier}",
        }]
        recipe["availability"] = "disabled"
        resign_recipe(recipe)
        mutations.append(("ambiguous even when non-live", ambiguous))

        for label, document in mutations:
            with self.subTest(label=label):
                self.assertIsNone(authenticated_recipe_registry(document))

        # The untouched control remains a single authenticated owner family.
        self.assertEqual(
            "consensus-backed-proxy",
            owning_recipe_family(
                authenticated_recipe_registry(base_document), "lei", "tlsnotary"
            ),
        )

    def test_signed_default_and_alternative_method_shapes_are_validated(self):
        invalid_methods = [
            ("kind list", {"kind": []}),
            ("kind object", {"kind": {}}),
            ("vc issuer null", {
                "kind": "verifiable-credential", "issuerAllowList": None,
            }),
            ("vc issuer scalar", {
                "kind": "verifiable-credential",
                "issuerAllowList": AUTHORITY_REF,
            }),
            ("vc issuer member", {
                "kind": "verifiable-credential", "issuerAllowList": [1],
            }),
            ("vc issuer noncanonical", {
                "kind": "verifiable-credential",
                "issuerAllowList": ["KEY:" + AUTHORITY_REF.split(":", 1)[1]],
            }),
            ("vc schema url", {
                "kind": "verifiable-credential", "schemaUrl": 1,
            }),
            ("tls endpoint missing", {"kind": "tlsnotary"}),
            ("tls endpoint", {"kind": "tlsnotary", "endpoint": 1}),
            ("tls session template", {
                "kind": "tlsnotary", "endpoint": "https://example.test",
                "sessionTemplate": 1,
            }),
            ("zktls provider missing", {
                "kind": "zktls", "programId": "program",
            }),
            ("zktls provider", {
                "kind": "zktls", "provider": 1, "programId": "program",
            }),
            ("zktls program missing", {
                "kind": "zktls", "provider": "reclaim",
            }),
            ("zktls program", {
                "kind": "zktls", "provider": "reclaim", "programId": 1,
            }),
            ("proxy endpoint missing", {"kind": "consensus-backed-proxy"}),
            ("proxy endpoint", {
                "kind": "consensus-backed-proxy", "endpoint": "invalid",
            }),
            ("proxy method missing", {
                "kind": "consensus-backed-proxy",
                "endpoint": {"urlTemplate": "https://example.test"},
            }),
            ("proxy method", {
                "kind": "consensus-backed-proxy",
                "endpoint": {
                    "method": "PUT", "urlTemplate": "https://example.test",
                },
            }),
            ("proxy method list", {
                "kind": "consensus-backed-proxy",
                "endpoint": {
                    "method": [], "urlTemplate": "https://example.test",
                },
            }),
            ("proxy method object", {
                "kind": "consensus-backed-proxy",
                "endpoint": {
                    "method": {}, "urlTemplate": "https://example.test",
                },
            }),
            ("proxy url missing", {
                "kind": "consensus-backed-proxy",
                "endpoint": {"method": "GET"},
            }),
            ("proxy url", {
                "kind": "consensus-backed-proxy",
                "endpoint": {"method": "GET", "urlTemplate": 1},
            }),
            ("proxy headers", {
                "kind": "consensus-backed-proxy",
                "endpoint": {
                    "method": "GET", "urlTemplate": "https://example.test",
                    "headers": [],
                },
            }),
            ("proxy header value", {
                "kind": "consensus-backed-proxy",
                "endpoint": {
                    "method": "GET", "urlTemplate": "https://example.test",
                    "headers": {"Accept": 1},
                },
            }),
            ("proxy body", {
                "kind": "consensus-backed-proxy",
                "endpoint": {
                    "method": "POST", "urlTemplate": "https://example.test",
                    "body": 1,
                },
            }),
            ("oauth provider missing", {
                "kind": "oauth-attested", "scopes": [], "maxTokenAgeSec": 1,
            }),
            ("oauth provider", {
                "kind": "oauth-attested", "provider": 1,
                "scopes": [], "maxTokenAgeSec": 1,
            }),
            ("oauth scopes missing", {
                "kind": "oauth-attested", "provider": "provider",
                "maxTokenAgeSec": 1,
            }),
            ("oauth scopes", {
                "kind": "oauth-attested", "provider": "provider",
                "scopes": "read", "maxTokenAgeSec": 1,
            }),
            ("oauth scope member", {
                "kind": "oauth-attested", "provider": "provider",
                "scopes": [1], "maxTokenAgeSec": 1,
            }),
            ("oauth age missing", {
                "kind": "oauth-attested", "provider": "provider", "scopes": [],
            }),
            ("oauth age boolean", {
                "kind": "oauth-attested", "provider": "provider", "scopes": [],
                "maxTokenAgeSec": True,
            }),
            ("evm chain missing", {
                "kind": "evm-rpc", "contract": "0x1", "method": "owner",
            }),
            ("evm chain boolean", {
                "kind": "evm-rpc", "chainId": True,
                "contract": "0x1", "method": "owner",
            }),
            ("evm contract missing", {
                "kind": "evm-rpc", "chainId": 1, "method": "owner",
            }),
            ("evm contract", {
                "kind": "evm-rpc", "chainId": 1,
                "contract": 1, "method": "owner",
            }),
            ("evm method missing", {
                "kind": "evm-rpc", "chainId": 1, "contract": "0x1",
            }),
            ("evm method", {
                "kind": "evm-rpc", "chainId": 1,
                "contract": "0x1", "method": 1,
            }),
            ("evm args", {
                "kind": "evm-rpc", "chainId": 1,
                "contract": "0x1", "method": "owner", "args": {},
            }),
            ("domain challenge missing", {"kind": "domain-tls-control"}),
            ("domain challenge", {
                "kind": "domain-tls-control", "challengeType": "smtp-01",
            }),
            ("domain challenge list", {
                "kind": "domain-tls-control", "challengeType": [],
            }),
            ("domain challenge object", {
                "kind": "domain-tls-control", "challengeType": {},
            }),
        ]

        self.assertFalse(verification_method_valid({
            "kind": "oauth-attested", "provider": "provider", "scopes": [],
            "maxTokenAgeSec": float("inf"),
        }))
        self.assertFalse(verification_method_valid({
            "kind": "evm-rpc", "chainId": float("nan"),
            "contract": "0x1", "method": "owner",
        }))
        # Out-of-profile integers cannot be signed because repository JCS
        # rejects them before signature creation; the field gate rejects them
        # independently as well.
        self.assertFalse(verification_method_valid({
            "kind": "oauth-attested", "provider": "provider", "scopes": [],
            "maxTokenAgeSec": SAFE_INT + 1,
        }))
        self.assertFalse(verification_method_valid({
            "kind": "evm-rpc", "chainId": SAFE_INT + 1,
            "contract": "0x1", "method": "owner",
        }))

        for label, invalid in invalid_methods:
            self.assertFalse(verification_method_valid(invalid), label)
            for position in ("default", "alternative"):
                with self.subTest(label=label, position=position):
                    document = copy.deepcopy(self.document)
                    recipes = document["trustedContext"]["recipeRegistry"]["recipes"]
                    if position == "default":
                        recipe = next(
                            item for item in recipes
                            if item["scheme"] == "key"
                        )
                        recipe["defaultMethod"] = copy.deepcopy(invalid)
                    else:
                        recipe = next(
                            item for item in recipes
                            if item["scheme"] == "lei"
                            and item["recipeVersion"] == 1
                        )
                        recipe["alternatives"] = [copy.deepcopy(invalid)]
                    resign_recipe(recipe)
                    self.assertIsNone(authenticated_recipe_registry(document))

    def test_valid_signed_method_shapes_preserve_unknown_metadata(self):
        valid_methods = [
            {"kind": "verifiable-credential"},
            {
                "kind": "verifiable-credential",
                "issuerAllowList": [AUTHORITY_REF],
                "schemaUrl": "https://example.test/schema.json",
            },
            {
                "kind": "tlsnotary", "endpoint": "https://example.test",
                "sessionTemplate": "audit",
            },
            {"kind": "zktls", "provider": "reclaim", "programId": "program"},
            {
                "kind": "consensus-backed-proxy",
                "endpoint": {
                    "method": "POST", "urlTemplate": "https://example.test",
                    "headers": {"Accept": "application/json"}, "body": "{}",
                },
            },
            {
                "kind": "oauth-attested", "provider": "provider",
                "scopes": ["read"], "maxTokenAgeSec": 0.5,
            },
            {
                "kind": "evm-rpc", "chainId": 1.5,
                "contract": "0x1", "method": "owner", "args": [],
            },
            {"kind": "domain-tls-control", "challengeType": "http-01"},
            {"kind": "domain-tls-control", "challengeType": "dns-01"},
            {"kind": "domain-tls-control", "challengeType": "tls-alpn-01"},
            {"kind": "self-signed", "futureSignedPolicy": {"version": 2}},
            {"kind": "demos-gcr-domain"},
        ]
        for method in valid_methods:
            with self.subTest(method=method["kind"]):
                self.assertTrue(verification_method_valid(method))

        vc_document = copy.deepcopy(self.document)
        for recipe in vc_document["trustedContext"]["recipeRegistry"]["recipes"]:
            method = recipe["defaultMethod"]
            if method["kind"] == "verifiable-credential":
                method["schemaUrl"] = "https://example.test/schema.json"
                method["futureSignedPolicy"] = {"version": 2}
                resign_recipe(recipe)
        recipes = authenticated_recipe_registry(vc_document)
        self.assertIsNotNone(recipes)
        self.assertEqual(
            {"version": 2},
            recipes[("did", "verifiable-credential", 1)][
                "defaultMethod"
            ]["futureSignedPolicy"],
        )
        _, vc_evaluation = self._case_evaluation("vet-ma3-verified-accept")
        self.assertTrue(execute_once(vc_evaluation, vc_document))

        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        for explicit in (True, False):
            with self.subTest(explicit=explicit):
                document = copy.deepcopy(self.document)
                recipe = next(
                    item for item in document["trustedContext"][
                        "recipeRegistry"
                    ]["recipes"]
                    if item["scheme"] == "lei" and item["recipeVersion"] == 1
                )
                alternative = recipe["alternatives"][0]
                alternative["sessionTemplate"] = "audit"
                alternative["futureSignedPolicy"] = {"version": 2}
                resign_recipe(recipe)
                source = copy.deepcopy(evaluation)
                member = source["input"]["requirement"]["required"][0]
                member["parameters"] = {"verificationMethod": "tlsnotary"}
                if not explicit:
                    member.pop("recipeVersion")
                changed = rebuild_direct_result(
                    source,
                    document,
                    lambda artifact: artifact.update(method="tlsnotary"),
                )
                set_result_attestation_family(
                    document, changed["input"]["resolvedResults"][0]
                )
                recipes = authenticated_recipe_registry(document)
                self.assertEqual(
                    {"version": 2},
                    recipes[("lei", "consensus-backed-proxy", 1)][
                        "alternatives"
                    ][0]["futureSignedPolicy"],
                )
                self.assertEqual("pass", execute_once(changed, document))

    def test_alternative_selection_has_no_unsupported_or_older_fallback(self):
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )

        unsupported_document = copy.deepcopy(self.document)
        unsupported = copy.deepcopy(evaluation)
        member = unsupported["input"]["requirement"]["required"][0]
        member["parameters"] = {"verificationMethod": "tlsnotary"}
        member["recipeVersion"] = 2
        self.assertEqual("error", execute_once(unsupported, unsupported_document))

        no_fallback_document = copy.deepcopy(self.document)
        context = no_fallback_document["trustedContext"]
        owner = next(
            recipe for recipe in context["recipeRegistry"]["recipes"]
            if recipe["scheme"] == "lei" and recipe["recipeVersion"] == 1
        )
        later = copy.deepcopy(owner)
        later["recipeVersion"] = 3
        later.pop("alternatives")
        resign_recipe(later)
        context["recipeRegistry"]["recipes"].append(later)
        append_recipe_authorities(context, later)
        no_fallback = copy.deepcopy(evaluation)
        member = no_fallback["input"]["requirement"]["required"][0]
        member.pop("recipeVersion")
        member["parameters"] = {"verificationMethod": "tlsnotary"}
        self.assertEqual("error", execute_once(no_fallback, no_fallback_document))

    def test_selected_alternative_refuses_a_result_from_the_default_method(self):
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        changed = copy.deepcopy(evaluation)
        changed["input"]["requirement"]["required"][0]["parameters"] = {
            "verificationMethod": "tlsnotary"
        }
        self.assertEqual("fail", execute_once(changed, self.document))

    def test_selector_cannot_be_laundered_through_a_oneof_verified_member(self):
        # The presented key is presence-only; a DIFFERENT same-scheme key has
        # the passing verified result.  §7.7.1 exact_selector_authorized: a
        # oneOf group that admits the selector scheme through verification
        # must be satisfied by exact presence or by another scheme (PCR-5).
        _, evaluation = self._case_evaluation(
            "vet-control-key-verified-selector-laundering-reject"
        )
        laundering = copy.deepcopy(evaluation)
        laundering["input"]["requirement"] = {
            "requirementVersion": "1",
            "primaryClaimSelector": "key",
            "required": [{"scheme": "key", "verificationRequired": False}],
            "oneOf": [[
                {"scheme": "key", "verificationRequired": True, "recipeVersion": 1},
                {"scheme": "lei", "verificationRequired": True, "recipeVersion": 1},
            ]],
        }
        self.assertEqual("fail", execute_once(laundering, self.document))

        exact_presence = copy.deepcopy(laundering)
        exact_presence["input"]["requirement"]["oneOf"][0].append(
            {"scheme": "key", "verificationRequired": False}
        )
        self.assertEqual("pass", execute_once(exact_presence, self.document))

    def test_exact_verified_selector_authorizes_a_oneof_only_member(self):
        # verifiedSelector is exact-claim evidence and does not require the
        # selector scheme to appear as a required member.
        case, evaluation = self._case_evaluation("vet-ma3-verified-accept")
        self.assertTrue(case["expectedOutput"])
        member = evaluation["input"]["requirement"]["required"]
        oneof_only = copy.deepcopy(evaluation)
        oneof_only["input"]["requirement"]["required"] = []
        oneof_only["input"]["requirement"]["oneOf"] = [member]
        self.assertTrue(execute_once(oneof_only, self.document))

        uncontrolled = copy.deepcopy(oneof_only)
        uncontrolled["input"]["requirement"]["primaryClaimSelector"] = "key"
        self.assertFalse(execute_once(uncontrolled, self.document))

    def test_presented_by_resolves_by_cf3_identity_without_throwing(self):
        # DACS-1 §6.3.2: presentedBy resolves to the claim with the same
        # canonical scheme and identifier; CF-3 parameters are not identity.
        _, evaluation = self._case_evaluation("vet-control-key-presentation-accept")
        presenter = fixture_private_key("presenter")

        def presented_as(refs):
            changed = copy.deepcopy(evaluation)
            bundle = changed["input"]["bundle"]
            original = next(
                c for c in bundle["claims"] if c["ref"] == bundle["presentedBy"]
            )
            bundle["claims"] = [
                c for c in bundle["claims"] if c is not original
            ] + [dict(original, ref=ref) for ref in refs]
            changed["input"]["bundle"] = resign_bundle(bundle, presenter, refs[0])
            self.assertTrue(verify_bundle(changed["input"]["bundle"]))
            return changed

        presented = evaluation["input"]["bundle"]["presentedBy"]
        qualified = presented_as([presented + "?purpose=session"])
        self.assertEqual("pass", execute_once(qualified, self.document))
        qualified["operation"] = "control-decision"
        self.assertEqual("pass", execute_once(qualified, self.document))

        # A byte-identical repeated claim is still one presented claim.
        repeated = presented_as([presented, presented])
        self.assertEqual("pass", execute_once(repeated, self.document))

        # Two different claims with the presented identity do not resolve uniquely.
        ambiguous = presented_as([presented + "?purpose=session", presented + "?purpose=audit"])
        self.assertEqual("fail", execute_once(ambiguous, self.document))
        ambiguous["operation"] = "control-decision"
        self.assertEqual("fail", execute_once(ambiguous, self.document))

    def test_composite_record_version_and_warning_shapes_are_enforced(self):
        case, evaluation = self._case_evaluation("vet-oneof-indeterminate-over-fail")
        record = evaluation["input"]["record"]

        def replay(mutate):
            document = copy.deepcopy(self.document)
            changed = copy.deepcopy(evaluation)
            mutate(changed["input"]["record"])
            changed["input"] = reanchor_composite_input(changed["input"], document)
            return execute_once(changed, document)

        valid_warning = {
            "claimRef": record["evaluatedParty"],
            "code": "AUTHORITY_UNAVAILABLE",
            "retryable": True,
            "suggestedRetryAfterMs": 1_000,
        }
        # WN-1: a well-formed warning never moves the decision.
        self.assertEqual(case["expectedOutput"], replay(lambda r: None))
        self.assertEqual(
            case["expectedOutput"],
            replay(lambda r: r.update(warnings=[dict(valid_warning)])),
        )
        for label, mutate in (
            ("unsupported recordVersion", lambda r: r.update(recordVersion="2")),
            ("missing recordVersion", lambda r: r.pop("recordVersion")),
            ("non-array warnings", lambda r: r.update(warnings="rate-limited")),
            ("empty warning code",
             lambda r: r.update(warnings=[dict(valid_warning, code="")])),
            ("non-boolean retryable",
             lambda r: r.update(warnings=[dict(valid_warning, retryable="yes")])),
            ("negative retry hint",
             lambda r: r.update(warnings=[dict(valid_warning, suggestedRetryAfterMs=-1)])),
        ):
            with self.subTest(label=label):
                self.assertEqual(
                    {"decision": "error", "reasons": ["aggregation authority invalid"]},
                    replay(mutate),
                )

    def test_results_attributable_only_to_presence_members_reject_the_record(self):
        case, evaluation = self._case_evaluation("vet-oneof-indeterminate-over-fail")

        def replay(requirement, decision):
            document = copy.deepcopy(self.document)
            changed = copy.deepcopy(evaluation)
            value = changed["input"]
            value["authority"]["vetInput"]["requirement"] = requirement
            invocation = value["authority"]["invocation"]
            members = [
                *requirement.get("required", []),
                *(member for group in requirement.get("oneOf", []) for member in group),
            ]
            for resolved in value["resolvedResults"]:
                member = next(
                    item for item in members
                    if item.get("scheme") == resolved["artifact"].get("scheme")
                )
                entry = next(
                    item for item in document["trustedContext"]["authenticatedResultProvenance"]
                    if canonical_bytes(item["ref"]) == canonical_bytes(resolved["ref"])
                    and item["serializedArtifactHash"] == resolved["serializedArtifactHash"]
                )
                entry["currentProductions"].append({
                    "invocation": invocation,
                    "requirementHash": hash_hex(requirement),
                    "memberHash": hash_hex(member),
                })
            value["record"]["requirementHash"] = hash_hex(requirement)
            value["record"]["overallDecision"] = decision
            changed["input"] = reanchor_composite_input(value, document)
            return execute_once(changed, document)

        original = evaluation["input"]["authority"]["vetInput"]["requirement"]
        # Control: an extra presence member of an uncommitted scheme leaves
        # every committed result attributable to a verified member.
        attributable = {
            **copy.deepcopy(original),
            "required": [{"scheme": "key", "verificationRequired": False}],
        }
        self.assertEqual(
            case["expectedOutput"],
            replay(attributable, case["expectedOutput"]["decision"]),
        )
        presence_only = {
            "requirementVersion": "1",
            "required": [
                {"scheme": "lei", "verificationRequired": False},
                {"scheme": "domain", "verificationRequired": False},
            ],
        }
        # Signed "pass" is exactly what presence replay alone would produce.
        self.assertEqual(
            {"decision": "error", "reasons": ["aggregation authority invalid"]},
            replay(presence_only, "pass"),
        )

    def test_aggregate_authority_bindings_are_each_load_bearing(self):
        case, evaluation = self._case_evaluation("vet-oneof-indeterminate-over-fail")
        invalid = {"decision": "error", "reasons": ["aggregation authority invalid"]}
        verifier = fixture_private_key("verifier")

        def replay(mutate_input=None, mutate_trusted=None, resign=False):
            document = copy.deepcopy(self.document)
            changed = copy.deepcopy(evaluation)
            value = changed["input"]
            invocation = document["trustedContext"]["vetInvocations"][
                value["authority"]["invocation"]
            ]
            receipt = document["trustedContext"]["authenticatedRecordReceipts"][
                invocation["recordReceiptId"]
            ]
            if mutate_input:
                mutate_input(value, document)
            if resign:
                changed["input"] = reanchor_composite_input(value, document)
            if mutate_trusted:
                mutate_trusted(changed["input"], invocation, receipt)
            return execute_once(changed, document)

        self.assertEqual(case["expectedOutput"], replay(resign=True))

        def other_session(value, document):
            sessions = document["trustedContext"]["authenticatedSessionStarts"]
            name = value["authority"]["authenticatedSessionStart"]
            sessions[name + "-copy"] = copy.deepcopy(sessions[name])
            value["authority"]["authenticatedSessionStart"] = name + "-copy"

        def verifier_presents_other_claim(value, document):
            identity = value["authority"]["vetInput"]["verifierIdentity"]
            other = public_ref(fixture_private_key("replacement-signer"))
            identity["claims"].append({"ref": other, "issuedAt": identity["presentedAt"]})
            identity["presentedBy"] = other
            value["authority"]["vetInput"]["verifierIdentity"] = resign_bundle(
                identity, verifier, public_ref(verifier)
            )

        def duplicate_commitment(value, document):
            value["record"]["dealSpecific"].append(
                copy.deepcopy(value["record"]["dealSpecific"][0])
            )
            value["resolvedResults"].append(copy.deepcopy(value["resolvedResults"][0]))

        def native_equals_logical(value, invocation, receipt):
            logical = invocation["recordAnchorBinding"]["logicalAddress"]
            value["recordRef"]["anchor"]["locator"] = logical
            invocation["recordAnchorBinding"]["nativeAddress"] = logical
            receipt["nativeAddress"] = logical

        signed = (
            ("bundleHash", lambda v, d: v["record"].update(bundleHash="00" * 32)),
            ("requirementHash", lambda v, d: v["record"].update(requirementHash="00" * 32)),
            ("committed result order",
             lambda v, d: v["record"]["dealSpecific"].reverse()),
            ("duplicate committed result", duplicate_commitment),
        )
        for label, mutate in signed:
            with self.subTest(label=label):
                self.assertEqual(invalid, replay(mutate, resign=True))
        unsigned = (
            ("vetInput actor", lambda v, d: v["authority"]["vetInput"].update(actor="seller")),
            ("vetInput attempt", lambda v, d: v["authority"]["vetInput"].update(attempt=2)),
            ("authenticated session name", other_session),
            ("verifier identity presentedBy", verifier_presents_other_claim),
            ("resolved order only", lambda v, d: v["resolvedResults"].reverse()),
        )
        for label, mutate in unsigned:
            with self.subTest(label=label):
                self.assertEqual(invalid, replay(mutate))
        trusted_now = self.document["trustedContext"]["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]["trustedNow"]
        receipts = (
            ("receipt observed after trusted time",
             lambda v, i, r: r.update(observedAt=trusted_now + 1)),
            ("block time after observation",
             lambda v, i, r: r["blockRef"].update(timestamp=r["observedAt"] + 1)),
            ("unestablished observation",
             lambda v, i, r: r.update(observationDisposition="inferred")),
            ("receipt content hash", lambda v, i, r: r.update(contentHash="00" * 32)),
            ("native equals logical without a declared identity mapping",
             native_equals_logical),
        )
        for label, mutate in receipts:
            with self.subTest(label=label):
                self.assertEqual(invalid, replay(mutate_trusted=mutate))

        flipped = replay(
            lambda v, d: v["record"].update(overallDecision="pass"), resign=True
        )
        self.assertEqual(
            {"decision": "error",
             "reasons": ["signed overallDecision does not match replay"]},
            flipped,
        )

    def _replay_aggregate(self, name, mutate, decision):
        """Mutate an aggregate input, sign ``decision``, and re-anchor it."""

        _, evaluation = self._case_evaluation(name)
        document = copy.deepcopy(self.document)
        changed = copy.deepcopy(evaluation)
        mutate(changed["input"], document)
        changed["input"]["record"]["overallDecision"] = decision
        changed["input"] = reanchor_composite_input(changed["input"], document)
        return execute_once(changed, document)

    def _committed_index(self, value, scheme):
        return next(
            index for index, item in enumerate(value["resolvedResults"])
            if item["artifact"]["scheme"] == scheme
        )

    def _replace_committed(self, value, document, index, mutate_artifact):
        """Swap one committed result for a re-signed, authenticated variant."""

        resolved = copy.deepcopy(value["resolvedResults"][index])
        mutate_artifact(resolved["artifact"])
        replacement = resign_result(
            resolved, fixture_private_key("authority"), AUTHORITY_REF
        )
        document["trustedContext"]["authenticatedResultArtifacts"].append({
            "ref": copy.deepcopy(replacement["ref"]),
            "serializedArtifactHash": replacement["serializedArtifactHash"],
        })
        old = value["resolvedResults"][index]["ref"]
        value["resolvedResults"][index] = replacement
        for field in ("freshness", "dealSpecific"):
            value["record"][field] = [
                copy.deepcopy(replacement["ref"]) if ref == old else ref
                for ref in value["record"][field]
            ]

    def test_aggregation_classifies_committed_results_not_bundle_pointers(self):
        # DACS-2 §7.7.1 classify_verified_member uses the record's committed
        # freshness ++ dealSpecific results; an empty committed set fails.
        def drop_lei(value, document):
            index = self._committed_index(value, "lei")
            ref = value["resolvedResults"].pop(index)["ref"]
            for field in ("freshness", "dealSpecific"):
                value["record"][field] = [
                    item for item in value["record"][field] if item != ref
                ]

        self.assertEqual(
            {"decision": "fail", "reasons": ["required failing or absent: lei"]},
            self._replay_aggregate(
                "vet-cross-accumulator-fail-over-error", drop_lei, "fail"
            ),
        )

        # A refreshed committed result counts even though the bundle claim
        # still points at the older, now uncommitted reference.
        def refresh_lei(value, document):
            self._replace_committed(
                value, document, self._committed_index(value, "lei"),
                lambda artifact: artifact.update(decision="pass"),
            )

        self.assertEqual(
            {"decision": "pass", "reasons": []},
            self._replay_aggregate(
                "vet-oneof-indeterminate-over-fail", refresh_lei, "pass"
            ),
        )

        # A committed result for another identity cannot satisfy the member.
        def other_identity(value, document):
            self._replace_committed(
                value, document, self._committed_index(value, "lei"),
                lambda artifact: artifact.update(
                    decision="pass", identifier="529900T8BM49AURSDO55"
                ),
            )

        case, _ = self._case_evaluation("vet-oneof-indeterminate-over-fail")
        self.assertEqual(
            case["expectedOutput"],
            self._replay_aggregate(
                "vet-oneof-indeterminate-over-fail", other_identity,
                "indeterminate",
            ),
        )

        # Qualification preflight covers every committed method for the
        # scheme, not only the one a bundle claim cites (CRQ-2).
        _, credential = self._case_evaluation("vet-ma3-verified-accept")
        uncited = credential["input"]["resolvedResults"][0]

        def commit_uncited(value, document):
            value["resolvedResults"].append(copy.deepcopy(uncited))
            value["record"]["dealSpecific"].append(copy.deepcopy(uncited["ref"]))

        self.assertEqual(
            {"decision": "error", "reasons": ["unresolved recipe family or version"]},
            self._replay_aggregate(
                "vet-oneof-indeterminate-over-fail", commit_uncited, "error"
            ),
        )

    def test_every_committed_result_needs_a_verified_member(self):
        invalid = {"decision": "error", "reasons": ["aggregation authority invalid"]}

        def requirement(req):
            def mutate(value, document):
                value["authority"]["vetInput"]["requirement"] = req
                value["record"]["requirementHash"] = hash_hex(req)
            return mutate

        # The committed domain result is attributable to no member.
        self.assertEqual(invalid, self._replay_aggregate(
            "vet-cross-accumulator-fail-over-error",
            requirement({"requirementVersion": "1", "required": [
                {"scheme": "lei", "verificationRequired": True, "recipeVersion": 1},
            ]}),
            "fail",
        ))
        # No member at all: every committed result is unattributable.
        self.assertEqual(invalid, self._replay_aggregate(
            "vet-cross-accumulator-fail-over-error",
            requirement({"requirementVersion": "1", "required": []}),
            "pass",
        ))

    def test_required_verified_selector_uses_the_generic_exact_claim_gate(self):
        # exact_selector_authorized: verifiedSelector is the presented claim's
        # own verified-and-fresh evidence, independent of member order and of
        # any one member's method/age/parameter constraints.
        case, evaluation = self._case_evaluation("vet-ma3-verified-accept")
        self.assertTrue(case["expectedOutput"])
        _, proxy_case = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        proxy = copy.deepcopy(proxy_case["input"]["resolvedResults"][0])
        proxy["artifact"]["identifier"] = "529900T8BM49AURSDO55"
        proxy = resign_result(proxy, fixture_private_key("authority"), AUTHORITY_REF)
        document = copy.deepcopy(self.document)
        document["trustedContext"]["authenticatedResultArtifacts"].append({
            "ref": copy.deepcopy(proxy["ref"]),
            "serializedArtifactHash": proxy["serializedArtifactHash"],
        })
        changed = copy.deepcopy(evaluation)
        bundle = changed["input"]["bundle"]
        bundle["claims"].append({
            "ref": "lei:529900T8BM49AURSDO55",
            "issuedAt": bundle["presentedAt"],
            "verifiedBy": copy.deepcopy(proxy["ref"]),
        })
        presenter = fixture_private_key("presenter")
        changed["input"]["bundle"] = resign_bundle(bundle, presenter, public_ref(presenter))
        changed["input"]["resolvedResults"].append(proxy)
        members = [
            {"scheme": "lei", "verificationRequired": True,
             "parameters": {"verificationMethod": "verifiable-credential"}},
            {"scheme": "lei", "verificationRequired": True,
             "parameters": {"verificationMethod": "consensus-backed-proxy"}},
        ]
        for order in (members, list(reversed(members))):
            with self.subTest(first=order[0]["parameters"]["verificationMethod"]):
                candidate = copy.deepcopy(changed)
                candidate["input"]["requirement"] = {
                    "requirementVersion": "1", "required": order,
                    "primaryClaimSelector": "lei",
                }
                self.assertTrue(execute_once(candidate, document))

    def test_json_nesting_depth_is_bounded_without_recursion_leaks(self):
        # CORE CF-5(5): depth 128 is admitted, 129 is rejected, and a host
        # recursion limit is never leaked as a verdict.
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        presenter = fixture_private_key("presenter")

        def nested(depth):
            value = 0
            for _ in range(depth):
                value = [value]
            return value

        def with_metadata(depth):
            changed = copy.deepcopy(evaluation)
            bundle = changed["input"]["bundle"]
            claim = next(c for c in bundle["claims"] if c["ref"].startswith("lei:"))
            claim["metadata"] = {"nested": nested(depth)}
            changed["input"]["bundle"] = resign_bundle(
                bundle, presenter, public_ref(presenter)
            )
            changed["input"]["requirement"] = {
                "requirementVersion": "1",
                "required": [{"scheme": "lei", "verificationRequired": False}],
            }
            return changed

        self.assertEqual(128, MAX_JSON_DEPTH)
        # bundle(1) > claims(2) > claim(3) > metadata(4) > nested lists.
        admitted = with_metadata(124)
        self.assertTrue(within_json_depth(admitted["input"]["bundle"]))
        self.assertEqual("pass", execute_once(admitted, self.document))
        refused = with_metadata(125)
        self.assertFalse(within_json_depth(refused["input"]["bundle"]))
        self.assertEqual("error", execute_once(refused, self.document))

        deep = copy.deepcopy(evaluation)
        deep["input"]["requirement"]["required"][0]["parameters"] = {
            "nested": nested(5_000)
        }
        self.assertEqual("error", execute_once(deep, self.document))
        _, aggregate = self._case_evaluation("vet-oneof-indeterminate-over-fail")
        unsigned_deep = copy.deepcopy(aggregate)
        unsigned_deep["input"]["authority"]["vetInput"]["requirement"] = {
            "nested": nested(5_000)
        }
        # No host recursion error escapes, even before hash binding rejects it.
        self.assertEqual(
            {"decision": "error", "reasons": ["aggregation authority invalid"]},
            execute_once(unsigned_deep, self.document),
        )
        # Re-signed so the requirement hash binds, the depth guard decides.
        deep_requirement = {"requirementVersion": "1", "required": nested(200)}

        def deep_aggregate(value, document):
            value["authority"]["vetInput"]["requirement"] = deep_requirement
            value["record"]["requirementHash"] = hash_hex(deep_requirement)

        self.assertEqual(
            {"decision": "error", "reasons": ["invalid bundle requirement"]},
            self._replay_aggregate(
                "vet-oneof-indeterminate-over-fail", deep_aggregate, "error"
            ),
        )

        # The bound applies to each artifact: a VerifyResult and a record.
        for depth, expected in ((126, "pass"), (127, "error")):
            with self.subTest(result_data_depth=depth + 2):
                document = copy.deepcopy(self.document)
                changed = rebuild_direct_result(
                    evaluation, document,
                    lambda a, depth=depth: a.update(data={"nested": nested(depth)}),
                )
                self.assertEqual(expected, execute_once(changed, document))
        case, _ = self._case_evaluation("vet-oneof-indeterminate-over-fail")
        for depth, expected in (
            (127, case["expectedOutput"]),
            (128, {"decision": "error", "reasons": ["aggregation authority invalid"]}),
        ):
            with self.subTest(record_depth=depth + 1):
                self.assertEqual(expected, self._replay_aggregate(
                    "vet-oneof-indeterminate-over-fail",
                    lambda value, document, depth=depth: value["record"].update(
                        extension=nested(depth)
                    ),
                    case["expectedOutput"]["decision"],
                ))

    def test_previously_unpinned_record_signal_and_binding_guards(self):
        _, evaluation = self._case_evaluation("vet-oneof-indeterminate-over-fail")
        invalid = {"decision": "error", "reasons": ["aggregation authority invalid"]}
        record = evaluation["input"]["record"]

        def replay(mutate_record=None, mutate_trusted=None):
            document = copy.deepcopy(self.document)
            changed = copy.deepcopy(evaluation)
            if mutate_record:
                mutate_record(changed["input"]["record"])
            changed["input"] = reanchor_composite_input(changed["input"], document)
            if mutate_trusted:
                invocation = document["trustedContext"]["vetInvocations"][
                    changed["input"]["authority"]["invocation"]
                ]
                mutate_trusted(invocation)
            return execute_once(changed, document)

        warning = {
            "claimRef": record["evaluatedParty"],
            "code": "AUTHORITY_UNAVAILABLE", "retryable": True,
        }
        signal = record["supplementary"][0]
        for label, mutate in (
            ("empty-string warnings", lambda r: r.update(warnings="")),
            ("object warnings", lambda r: r.update(warnings={})),
            ("non-string warning claimRef",
             lambda r: r.update(warnings=[dict(warning, claimRef=1)])),
            ("signal extra member",
             lambda r: r["supplementary"][0].update(rogue=1)),
            ("signal object value",
             lambda r: r["supplementary"][0].update(value={})),
            ("signal string observedAt",
             lambda r: r["supplementary"][0].update(observedAt=str(signal["observedAt"]))),
            ("signal empty source",
             lambda r: r["supplementary"][0].update(source="")),
        ):
            with self.subTest(label=label):
                self.assertEqual(invalid, replay(mutate))
        self.assertEqual(invalid, replay(mutate_trusted=lambda invocation: invocation[
            "recordAnchorBinding"
        ].update(writer=invocation["expectedVerifier"])))

    def test_required_verified_selector_member_disables_the_presence_path(self):
        # §7.7.1: when a required member verifies the selector scheme, only the
        # presented claim's own verified evidence can authorize the selector;
        # an exact presence member plus a DIFFERENT verified claim cannot.
        _, evaluation = self._case_evaluation(
            "vet-control-key-verified-selector-laundering-reject"
        )
        changed = copy.deepcopy(evaluation)
        changed["input"]["requirement"] = {
            "requirementVersion": "1",
            "primaryClaimSelector": "key",
            "required": [
                {"scheme": "key", "verificationRequired": True, "recipeVersion": 1},
                {"scheme": "key", "verificationRequired": False},
            ],
        }
        self.assertEqual("fail", execute_once(changed, self.document))
        without_selector = copy.deepcopy(changed)
        without_selector["input"]["requirement"].pop("primaryClaimSelector")
        self.assertEqual("pass", execute_once(without_selector, self.document))

    def test_verifier_identity_presentation_signature_is_load_bearing(self):
        _, evaluation = self._case_evaluation("vet-oneof-indeterminate-over-fail")
        changed = copy.deepcopy(evaluation)
        signature = changed["input"]["authority"]["vetInput"]["verifierIdentity"][
            "presentation"
        ]["signatures"][0]
        signature["signature"] = (
            ("A" if signature["signature"][0] != "A" else "B")
            + signature["signature"][1:]
        )
        self.assertEqual(
            {"decision": "error", "reasons": ["aggregation authority invalid"]},
            execute_once(changed, self.document),
        )

    def test_verifier_identity_identical_claim_repetition_collapses(self):
        case, evaluation = self._case_evaluation("vet-oneof-indeterminate-over-fail")
        expected = case["expectedOutput"]
        verifier = fixture_private_key("verifier")
        verifier_ref = public_ref(verifier)

        def with_claims(claims):
            changed = copy.deepcopy(evaluation)
            vet_input = changed["input"]["authority"]["vetInput"]
            identity = vet_input["verifierIdentity"]
            self.assertEqual(verifier_ref, identity["presentedBy"])
            identity["claims"] = copy.deepcopy(claims)
            vet_input["verifierIdentity"] = resign_bundle(
                identity, verifier, verifier_ref
            )
            return changed

        original = evaluation["input"]["authority"]["vetInput"][
            "verifierIdentity"
        ]["claims"][0]
        repeated = with_claims([original, original])
        self.assertEqual(expected, execute_once(repeated, self.document))
        self.assertEqual(
            expected,
            reconstruct_historical_once(repeated, self.document),
        )

        qualified = dict(original, ref=verifier_ref + "?purpose=audit")
        invalid = {
            "decision": "error",
            "reasons": ["aggregation authority invalid"],
        }
        for claims in ([original, qualified], [qualified, original]):
            with self.subTest(order=[item["ref"] for item in claims]):
                ambiguous = with_claims(claims)
                self.assertEqual(invalid, execute_once(ambiguous, self.document))
                self.assertEqual(
                    invalid,
                    reconstruct_historical_once(ambiguous, self.document),
                )

    def _commit_extra(self, value, document, scheme, mutate_artifact):
        """Commit one more authenticated result derived from a committed one."""

        source = copy.deepcopy(
            value["resolvedResults"][self._committed_index(value, scheme)]
        )
        mutate_artifact(source["artifact"])
        extra = resign_result(source, fixture_private_key("authority"), AUTHORITY_REF)
        document["trustedContext"]["authenticatedResultArtifacts"].append({
            "ref": copy.deepcopy(extra["ref"]),
            "serializedArtifactHash": extra["serializedArtifactHash"],
        })
        value["resolvedResults"].append(extra)
        value["record"]["dealSpecific"].append(copy.deepcopy(extra["ref"]))
        return extra

    def _resign_aggregate_bundle(self, value):
        presenter = fixture_private_key("presenter")
        bundle = resign_bundle(
            value["authority"]["vetInput"]["bundleToVet"], presenter,
            public_ref(presenter),
        )
        value["authority"]["vetInput"]["bundleToVet"] = bundle
        value["record"]["bundleHash"] = hash_hex(
            {key: item for key, item in bundle.items() if key != "presentation"}
        )

    def test_direct_input_cannot_select_aggregation_semantics(self):
        # Only authenticate_production_aggregate may classify committed
        # results; a caller-supplied JSON field is inert (CORE §11.1.2).
        case, evaluation = self._case_evaluation("vet-findclaim-decision")
        self.assertFalse(case["expectedOutput"])
        _, source = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        changed = copy.deepcopy(evaluation)
        changed["input"]["resolvedResults"].append(
            copy.deepcopy(source["input"]["resolvedResults"][0])
        )
        self.assertFalse(execute_once(changed, self.document))
        changed["input"]["committedResultsOnly"] = True
        self.assertFalse(execute_once(changed, self.document))

    def test_unowned_committed_results_do_not_participate_or_steer(self):
        # A committed result whose owning claim is expired, or whose identity
        # no bundle claim has, is not current evidence for the member: it
        # cannot turn an error/indeterminate group into a counterparty fail.
        for name in ("vet-oneof-indeterminate-over-fail", "vet-oneof-error-over-fail"):
            case, _ = self._case_evaluation(name)
            decision = case["expectedOutput"]["decision"]

            def foreign(value, document):
                self._commit_extra(value, document, "domain", lambda a: a.update(
                    identifier="example.net", decision="pass"
                ))

            def expired_owner(value, document):
                extra = self._commit_extra(value, document, "domain", lambda a: a.update(
                    identifier="example.org", decision="indeterminate"
                ))
                value["authority"]["vetInput"]["bundleToVet"]["claims"].append({
                    "ref": "domain:example.org",
                    "issuedAt": value["record"]["generatedAt"] - 2,
                    "expiresAt": value["record"]["generatedAt"] - 1,
                    "verifiedBy": copy.deepcopy(extra["ref"]),
                })
                self._resign_aggregate_bundle(value)

            for label, mutate in (("foreign identity", foreign), ("expired owner", expired_owner)):
                with self.subTest(case=name, label=label):
                    self.assertEqual(
                        case["expectedOutput"],
                        self._replay_aggregate(name, mutate, decision),
                    )

    def test_committed_results_bind_their_exact_owner_and_either_list(self):
        # With two same-scheme claims, a committed pass belongs to the claim
        # with its identity; and freshness results count like dealSpecific.
        def second_owner(value, document):
            value["authority"]["vetInput"]["bundleToVet"]["claims"].append({
                "ref": "lei:529900T8BM49AURSDO55",
                "issuedAt": value["record"]["generatedAt"] - 1,
            })
            self._resign_aggregate_bundle(value)
            self._replace_committed(
                value, document, self._committed_index(value, "lei"),
                lambda a: a.update(identifier="529900T8BM49AURSDO55", decision="pass"),
            )

        def refresh_in_freshness(value, document):
            index = self._committed_index(value, "lei")
            self._replace_committed(
                value, document, index, lambda a: a.update(decision="pass")
            )
            moved = value["resolvedResults"].pop(index)
            value["record"]["dealSpecific"] = [
                ref for ref in value["record"]["dealSpecific"] if ref != moved["ref"]
            ]
            value["record"]["freshness"] = [copy.deepcopy(moved["ref"])]
            value["resolvedResults"].insert(0, moved)

        for label, mutate in (("second owner", second_owner), ("freshness", refresh_in_freshness)):
            with self.subTest(label=label):
                self.assertEqual(
                    {"decision": "pass", "reasons": []},
                    self._replay_aggregate(
                        "vet-oneof-indeterminate-over-fail", mutate, "pass"
                    ),
                )

    def test_duplicate_commitment_under_another_version_label_rejects(self):
        def relabel(value, document):
            index = self._committed_index(value, "lei")
            duplicate = copy.deepcopy(value["resolvedResults"][index])
            duplicate["ref"]["recipeVersion"] = 2
            document["trustedContext"]["authenticatedResultArtifacts"].append({
                "ref": copy.deepcopy(duplicate["ref"]),
                "serializedArtifactHash": duplicate["serializedArtifactHash"],
            })
            value["resolvedResults"].append(duplicate)
            value["record"]["dealSpecific"].append(copy.deepcopy(duplicate["ref"]))

        def second_anchor(value, document):
            index = self._committed_index(value, "lei")
            duplicate = copy.deepcopy(value["resolvedResults"][index])
            duplicate["ref"]["anchor"]["locator"] += "-copy"
            document["trustedContext"]["authenticatedResultArtifacts"].append({
                "ref": copy.deepcopy(duplicate["ref"]),
                "serializedArtifactHash": duplicate["serializedArtifactHash"],
            })
            value["resolvedResults"].append(duplicate)
            value["record"]["dealSpecific"].append(copy.deepcopy(duplicate["ref"]))

        def mislabelled(value, document):
            index = self._committed_index(value, "lei")
            old = copy.deepcopy(value["resolvedResults"][index]["ref"])
            value["resolvedResults"][index]["ref"]["recipeVersion"] = 2
            document["trustedContext"]["authenticatedResultArtifacts"].append({
                "ref": copy.deepcopy(value["resolvedResults"][index]["ref"]),
                "serializedArtifactHash":
                    value["resolvedResults"][index]["serializedArtifactHash"],
            })
            value["record"]["dealSpecific"] = [
                copy.deepcopy(value["resolvedResults"][index]["ref"]) if ref == old else ref
                for ref in value["record"]["dealSpecific"]
            ]

        for label, mutate in (
            ("second version label", relabel),
            ("second anchor", second_anchor),
            ("single mislabelled reference", mislabelled),
        ):
            with self.subTest(label=label):
                self.assertEqual(
                    {"decision": "error", "reasons": ["aggregation authority invalid"]},
                    self._replay_aggregate(
                        "vet-oneof-indeterminate-over-fail", mutate, "indeterminate"
                    ),
                )

    def test_number_spelling_does_not_change_a_verdict(self):
        # CORE CF-5(4): 1900000060000 and 1900000060000.0 are one JSON value
        # with the same JCS bytes, so the verdict must not depend on spelling.
        case, evaluation = self._case_evaluation(
            "dacs1-freshness-fail-closed", "expiresOnly"
        )
        self.assertTrue(case["expectedOutput"]["expiresOnly"])
        expected = execute_once(evaluation, self.document)
        self.assertTrue(expected)
        changed = copy.deepcopy(evaluation)
        for claim in changed["input"]["bundle"]["claims"]:
            if "expiresAt" in claim:
                claim["expiresAt"] = float(claim["expiresAt"])
        self.assertTrue(verify_bundle(integral_numbers(changed["input"]["bundle"])))
        self.assertEqual(expected, execute_once(changed, self.document))

        aggregate_case, aggregate = self._case_evaluation(
            "vet-oneof-indeterminate-over-fail"
        )
        respelled = copy.deepcopy(aggregate)
        signal = respelled["input"]["record"]["supplementary"][0]
        signal["observedAt"] = float(signal["observedAt"])
        self.assertEqual(
            aggregate_case["expectedOutput"], execute_once(respelled, self.document)
        )

    def test_non_current_results_cannot_reach_qualification_preflight(self):
        # CRQ-1: preflight operates only on results whose governing §6.3.2
        # window has passed.  A stale or expired-owner result for an
        # unresolvable family therefore cannot turn a counterparty "fail"
        # into a permanent "error" (VPC-4).
        case, evaluation = self._case_evaluation("vet-cross-accumulator-fail-over-error")
        _, credential = self._case_evaluation("vet-ma3-verified-accept")

        def commit_credential(value, document, *, identifier=None, valid_until=None):
            source = copy.deepcopy(credential["input"]["resolvedResults"][0])
            if identifier is not None:
                source["artifact"]["identifier"] = identifier
            if valid_until is not None:
                source["artifact"]["validUntil"] = valid_until
            extra = resign_result(source, fixture_private_key("authority"), AUTHORITY_REF)
            trusted = document["trustedContext"]["authenticatedResultArtifacts"]
            if all(canonical_bytes(item["ref"]) != canonical_bytes(extra["ref"]) for item in trusted):
                trusted.append({
                    "ref": copy.deepcopy(extra["ref"]),
                    "serializedArtifactHash": extra["serializedArtifactHash"],
                })
            value["resolvedResults"].append(extra)
            value["record"]["dealSpecific"].append(copy.deepcopy(extra["ref"]))
            return extra

        def stale(value, document):
            commit_credential(
                value, document, valid_until=value["record"]["generatedAt"] - 1
            )

        def expired_owner(value, document):
            extra = commit_credential(value, document, identifier="529900T8BM49AURSDO55")
            value["authority"]["vetInput"]["bundleToVet"]["claims"].append({
                "ref": "lei:529900T8BM49AURSDO55",
                "issuedAt": value["record"]["generatedAt"] - 2,
                "expiresAt": value["record"]["generatedAt"] - 1,
                "verifiedBy": copy.deepcopy(extra["ref"]),
            })
            self._resign_aggregate_bundle(value)

        def current(value, document):
            commit_credential(value, document)

        for label, mutate in (("stale", stale), ("expired owner", expired_owner)):
            with self.subTest(label=label):
                self.assertEqual(
                    case["expectedOutput"],
                    self._replay_aggregate(
                        "vet-cross-accumulator-fail-over-error", mutate, "fail"
                    ),
                )
        # Control: the same result while current does reach preflight.
        self.assertEqual(
            {"decision": "error", "reasons": ["unresolved recipe family or version"]},
            self._replay_aggregate(
                "vet-cross-accumulator-fail-over-error", current, "error"
            ),
        )

        # Direct evaluation: a stale cited result is excluded before preflight.
        direct_case, direct = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        now = self.document["trustedContext"]["vetInvocations"][
            direct["input"]["authority"]["invocation"]
        ]["trustedNow"]
        for valid_until, expected in ((now - 1, direct_case["expectedOutput"]), (now, "error")):
            with self.subTest(direct_valid_until=valid_until - now):
                document = copy.deepcopy(self.document)
                source = copy.deepcopy(credential["input"]["resolvedResults"][0])
                source["artifact"]["identifier"] = "529900T8BM49AURSDO55"
                source["artifact"]["validUntil"] = valid_until
                extra = resign_result(source, fixture_private_key("authority"), AUTHORITY_REF)
                document["trustedContext"]["authenticatedResultArtifacts"].append({
                    "ref": copy.deepcopy(extra["ref"]),
                    "serializedArtifactHash": extra["serializedArtifactHash"],
                })
                changed = copy.deepcopy(direct)
                changed["input"]["resolvedResults"].append(extra)
                changed["input"]["bundle"]["claims"].append({
                    "ref": "lei:529900T8BM49AURSDO55",
                    "issuedAt": changed["input"]["bundle"]["presentedAt"],
                    "verifiedBy": copy.deepcopy(extra["ref"]),
                })
                presenter = fixture_private_key("presenter")
                changed["input"]["bundle"] = resign_bundle(
                    changed["input"]["bundle"], presenter, public_ref(presenter)
                )
                self.assertEqual(expected, execute_once(changed, document))

    def test_malformed_signed_results_error_even_when_stale(self):
        # §7.5 member types are result validity, not qualification: a stale
        # window cannot hide a malformed authority-signed result (CRQ-1).
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        now = self.document["trustedContext"]["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]["trustedNow"]
        for label, mutate in (
            ("unknown decision", lambda a: a.update(decision="bogus")),
            ("null decision", lambda a: a.update(decision=None)),
            ("missing reason", lambda a: a.pop("reason")),
            ("non-string reason", lambda a: a.update(reason=7)),
            ("non-object data", lambda a: a.update(data=[])),
        ):
            for stale in (False, True):
                with self.subTest(label=label, stale=stale):
                    document = copy.deepcopy(self.document)
                    changed = rebuild_direct_result(
                        evaluation, document,
                        lambda a, mutate=mutate, stale=stale: (
                            mutate(a), stale and a.update(validUntil=now - 1)
                        ),
                    )
                    self.assertEqual("error", execute_once(changed, document))

        def stale_bogus(value, document):
            self._replace_committed(
                value, document, self._committed_index(value, "lei"),
                lambda a: a.update(
                    decision="bogus", validUntil=value["record"]["generatedAt"] - 1
                ),
            )

        self.assertEqual(
            {"decision": "error", "reasons": ["aggregation authority invalid"]},
            self._replay_aggregate(
                "vet-cross-accumulator-fail-over-error", stale_bogus, "fail"
            ),
        )

    def test_claim_times_are_finite_numbers_for_matching_and_control(self):
        # DACS-1 declares these timestamps as numbers.  Fractional and
        # negative values retain their ordinary chronological meaning; only
        # booleans, non-finite values and non-numbers are malformed.
        _, evaluation = self._case_evaluation("vet-ma3-verified-accept")
        now = self.document["trustedContext"]["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]["trustedNow"]
        presenter = fixture_private_key("presenter")

        def control(field, value):
            changed = copy.deepcopy(evaluation)
            changed["operation"] = "control-decision"
            bundle = changed["input"]["bundle"]
            next(c for c in bundle["claims"] if c["ref"] == bundle["presentedBy"])[
                field
            ] = value
            changed["input"]["bundle"] = resign_bundle(
                bundle, presenter, public_ref(presenter)
            )
            return execute_once(changed, self.document)

        self.assertEqual("pass", control("expiresAt", now))
        self.assertEqual("fail", control("expiresAt", now - 1))
        self.assertEqual("fail", control("expiresAt", now - 86_400_000.5))
        self.assertEqual("fail", control("expiresAt", -1))
        for field, value in (
            ("expiresAt", "expired"), ("expiresAt", None),
            ("issuedAt", "yesterday"),
        ):
            with self.subTest(field=field, value=value):
                self.assertEqual("error", control(field, value))
        # An integral float spelling is the same JSON value (CF-5(4)).
        self.assertEqual("fail", control("expiresAt", float(now - 1)))
        # JSON booleans are not numbers, and 0 is a valid (long-past) time.
        for value in (True, False):
            with self.subTest(boolean=value):
                self.assertEqual("error", control("expiresAt", value))
        self.assertEqual("fail", control("expiresAt", 0))
        self.assertEqual("pass", control("issuedAt", 0))

        # The rule covers every claim and every path, not only the
        # presented claim under control-decision.
        _, direct = self._case_evaluation("vet-control-existence-only-lei-supporting-context")
        for field, expected in (("issuedAt", "pass"), ("expiresAt", "pass")):
            with self.subTest(path="decision", field=field):
                changed = copy.deepcopy(direct)
                bundle = changed["input"]["bundle"]
                other = next(c for c in bundle["claims"] if c["ref"] != bundle["presentedBy"])
                other[field] = now + 0.5
                changed["input"]["bundle"] = resign_bundle(
                    bundle, presenter, public_ref(presenter)
                )
                self.assertEqual(expected, execute_once(changed, self.document))

        def aggregate_claim_time(value, document):
            bundle = value["authority"]["vetInput"]["bundleToVet"]
            bundle["claims"][-1]["issuedAt"] = value["record"]["generatedAt"] - 0.5
            self._resign_aggregate_bundle(value)

        case, _ = self._case_evaluation("vet-oneof-indeterminate-over-fail")
        self.assertEqual(
            case["expectedOutput"],
            self._replay_aggregate(
                "vet-oneof-indeterminate-over-fail", aggregate_claim_time,
                "indeterminate",
            ),
        )

    def test_presented_at_is_a_finite_diagnostic_number(self):
        _, evaluation = self._case_evaluation("vet-ma3-verified-accept")
        presenter = fixture_private_key("presenter")
        for value in (0.5, -0.5):
            with self.subTest(value=value):
                changed = copy.deepcopy(evaluation)
                bundle = changed["input"]["bundle"]
                bundle["presentedAt"] = value
                changed["input"]["bundle"] = resign_bundle(
                    bundle, presenter, public_ref(presenter)
                )
                self.assertTrue(execute_once(changed, self.document))
        for value in (True, "0"):
            with self.subTest(value=repr(value)):
                changed = copy.deepcopy(evaluation)
                bundle = changed["input"]["bundle"]
                bundle["presentedAt"] = value
                changed["input"]["bundle"] = resign_bundle(
                    bundle, presenter, public_ref(presenter)
                )
                self.assertFalse(execute_once(changed, self.document))
        for value in (float("nan"), float("inf")):
            with self.subTest(value=repr(value)):
                changed = copy.deepcopy(evaluation)
                changed["input"]["bundle"]["presentedAt"] = value
                self.assertFalse(execute_once(changed, self.document))

    def test_stale_pass_does_not_participate_beside_a_current_non_pass(self):
        # CRQ-2: a result outside its window "does not participate,
        # regardless of its decision" -- it is not a counterparty fail.
        case, _ = self._case_evaluation("vet-oneof-error-over-fail")

        def stale_pass(value, document):
            self._commit_extra(value, document, "domain", lambda a: a.update(
                decision="pass", validUntil=value["record"]["generatedAt"] - 1,
            ))

        self.assertEqual(
            case["expectedOutput"],
            self._replay_aggregate(
                "vet-oneof-error-over-fail", stale_pass,
                case["expectedOutput"]["decision"],
            ),
        )

    def _aggregate_current_pass_control(
        self, *, r2_age=0, max_age=0.5, compatibility_profile=False,
        presence_only_domain=False, claim_expiry_offset=None,
    ):
        """Keep signatures, receipt, provenance, and profile binding current."""

        _, evaluation = self._case_evaluation(
            "vet-oneof-indeterminate-over-fail"
        )
        generated_at = evaluation["input"]["record"]["generatedAt"]
        invocation_id = evaluation["input"]["authority"]["invocation"]
        document = copy.deepcopy(self.document)
        changed = copy.deepcopy(evaluation)
        value = changed["input"]
        requirement = value["authority"]["vetInput"]["requirement"]
        members = requirement["oneOf"][0]
        lei_member = next(item for item in members if item["scheme"] == "lei")
        if max_age is None:
            lei_member.pop("maxAge", None)
        else:
            lei_member["maxAge"] = max_age
        if compatibility_profile:
            members.append({"scheme": "cci-lei", "verificationRequired": False})
        if presence_only_domain:
            domain_member = next(
                item for item in members if item["scheme"] == "domain"
            )
            domain_member.clear()
            domain_member.update(scheme="domain", verificationRequired=False)
        requirement_hash = hash_hex(requirement)
        value["record"]["requirementHash"] = requirement_hash

        # The only invalid premise in an attribution negative is that a
        # committed domain result has no verified requirement member.
        for resolved in value["resolvedResults"]:
            member = next(
                item for item in members
                if item["scheme"] == resolved["artifact"]["scheme"]
            )
            set_result_provenance(
                document,
                resolved,
                current=[{
                    "invocation": invocation_id,
                    "requirementHash": requirement_hash,
                    "memberHash": hash_hex(member),
                }],
            )
        r2_verified_at = generated_at - r2_age
        self._commit_extra(
            value,
            document,
            "lei",
            lambda artifact: artifact.update(
                decision="pass",
                reason="fresh pass beside maxAge-stale result",
                fetchedAt=r2_verified_at,
                verifiedAt=r2_verified_at,
            ),
        )
        if claim_expiry_offset is not None:
            claim = next(
                item
                for item in value["authority"]["vetInput"]["bundleToVet"]["claims"]
                if item["ref"].startswith("lei:")
            )
            claim["expiresAt"] = generated_at + claim_expiry_offset
            self._resign_aggregate_bundle(value)
        value["record"]["overallDecision"] = "pass"
        changed["input"] = reanchor_composite_input(value, document)

        invocation = document["trustedContext"]["vetInvocations"][invocation_id]
        receipt = document["trustedContext"]["authenticatedRecordReceipts"][
            invocation["recordReceiptId"]
        ]
        receipt["observedAt"] = generated_at
        receipt["blockRef"]["timestamp"] = generated_at
        invocation["trustedNow"] = generated_at
        if compatibility_profile:
            _, distinct = self._case_evaluation("dacs1-cci-lei-defect")
            profile_invocation = self.document["trustedContext"]["vetInvocations"][
                distinct["input"]["authority"]["invocation"]
            ]
            invocation["compatibilityProfile"] = profile_invocation[
                "compatibilityProfile"
            ]
            invocation["compatibilityRequirementHash"] = requirement_hash
        return changed, document

    @staticmethod
    def _aggregate_at(evaluation, document, trusted_now):
        moved = copy.deepcopy(document)
        invocation_id = evaluation["input"]["authority"]["invocation"]
        moved["trustedContext"]["vetInvocations"][invocation_id][
            "trustedNow"
        ] = trusted_now
        return moved

    def test_max_age_stale_result_is_inert_beside_current_pass(self):
        # DACS-2 §7.7.1 requalifies only results that participated at the
        # signed generatedAt. R1 is already outside maxAge; R2 participates.
        changed, document = self._aggregate_current_pass_control()
        generated_at = changed["input"]["record"]["generatedAt"]

        expected = {"decision": "pass", "reasons": []}
        invalid = {"decision": "error", "reasons": ["aggregation authority invalid"]}
        self.assertEqual(expected, reconstruct_historical_once(changed, document))
        self.assertEqual(expected, execute_once(changed, document))
        self.assertEqual(expected, execute_once(
            changed, self._aggregate_at(changed, document, generated_at + 500)
        ))
        expired = self._aggregate_at(changed, document, generated_at + 501)
        self.assertEqual(invalid, execute_once(changed, expired))
        self.assertEqual(expected, reconstruct_historical_once(changed, expired))

        # Participation at generatedAt is inclusive too: R2 exactly maxAge old
        # at generatedAt participates, so it is requalified at trustedNow.
        changed, document = self._aggregate_current_pass_control(r2_age=500)
        self.assertEqual(expected, execute_once(changed, document))
        expired = self._aggregate_at(changed, document, generated_at + 1)
        self.assertEqual(invalid, execute_once(changed, expired))
        self.assertEqual(expected, reconstruct_historical_once(changed, expired))

    def test_profile_aggregate_requalifies_max_age_with_accepting_boundary(self):
        expected = {"decision": "pass", "reasons": []}
        invalid = {"decision": "error", "reasons": ["aggregation authority invalid"]}
        for profile in (False, True):
            for r2_age in (0, 500):
                with self.subTest(profile=profile, r2_age=r2_age):
                    changed, document = self._aggregate_current_pass_control(
                        r2_age=r2_age, compatibility_profile=profile
                    )
                    generated_at = changed["input"]["record"]["generatedAt"]
                    boundary = generated_at + 500 - r2_age
                    at_boundary = self._aggregate_at(changed, document, boundary)
                    expired = self._aggregate_at(changed, document, boundary + 1)
                    self.assertEqual(expected, execute_once(changed, at_boundary))
                    self.assertEqual(invalid, execute_once(changed, expired))
                    self.assertEqual(
                        expected, reconstruct_historical_once(changed, expired)
                    )
                    # The real external JSON entry point must enforce the same
                    # current-authorization refusal, not only the fixture helper.
                    raw = json.dumps(changed, separators=(",", ":")).encode("utf-8")
                    self.assertEqual(expected, execute_external_once(raw, at_boundary))
                    self.assertEqual(invalid, execute_external_once(raw, expired))

    def test_profile_aggregate_requalifies_governing_claim_freshness(self):
        expected = {"decision": "pass", "reasons": []}
        invalid = {"decision": "error", "reasons": ["aggregation authority invalid"]}
        for profile in (False, True):
            with self.subTest(profile=profile):
                changed, document = self._aggregate_current_pass_control(
                    max_age=None, compatibility_profile=profile,
                    claim_expiry_offset=500,
                )
                generated_at = changed["input"]["record"]["generatedAt"]
                at_boundary = self._aggregate_at(changed, document, generated_at + 500)
                expired = self._aggregate_at(changed, document, generated_at + 501)
                self.assertEqual(expected, execute_once(changed, at_boundary))
                self.assertEqual(invalid, execute_once(changed, expired))
                self.assertEqual(expected, reconstruct_historical_once(changed, expired))

    def test_profile_aggregate_rejects_unattributable_committed_result(self):
        expected = {"decision": "pass", "reasons": []}
        invalid = {"decision": "error", "reasons": ["aggregation authority invalid"]}
        for profile in (False, True):
            with self.subTest(profile=profile):
                control, control_document = self._aggregate_current_pass_control(
                    compatibility_profile=profile
                )
                self.assertEqual(expected, execute_once(control, control_document))
                changed, document = self._aggregate_current_pass_control(
                    compatibility_profile=profile, presence_only_domain=True,
                )
                self.assertEqual(invalid, execute_once(changed, document))
                self.assertEqual(invalid, reconstruct_historical_once(changed, document))
                raw = json.dumps(changed, separators=(",", ":")).encode("utf-8")
                self.assertEqual(invalid, execute_external_once(raw, document))

    def test_number_normalisation_is_exact_copying_and_cycle_safe(self):
        # Fractional numbers keep their value (signed bytes unchanged), the
        # caller's input is not modified, explicit synthetic admission
        # normalises before aggregate execution, and an in-process cycle is an
        # error, not a hang.
        self.assertEqual({"a": [1, 0.97, -0.5]}, integral_numbers({"a": [1.0, 0.97, -0.5]}))
        case, evaluation = self._case_evaluation("vet-oneof-indeterminate-over-fail")
        document = copy.deepcopy(self.document)
        fractional = copy.deepcopy(evaluation)
        fractional["input"]["record"]["supplementary"][0]["value"] = 0.97
        fractional["input"] = reanchor_composite_input(fractional["input"], document)
        self.assertEqual(case["expectedOutput"], execute_once(fractional, document))

        respelled = copy.deepcopy(evaluation)
        signal = respelled["input"]["record"]["supplementary"][0]
        signal["observedAt"] = float(signal["observedAt"])
        before = copy.deepcopy(respelled)
        self.assertEqual(case["expectedOutput"], execute_once(respelled, self.document))
        self.assertIs(float, type(respelled["input"]["record"]["supplementary"][0]["observedAt"]))
        self.assertEqual(before, respelled)

        shared = {"k": 1.0}
        copied = integral_numbers({"x": shared, "y": shared})
        self.assertEqual({"x": {"k": 1}, "y": {"k": 1}}, copied)
        self.assertIs(float, type(shared["k"]))

        _, direct = self._case_evaluation("vet-control-key-presentation-accept")
        cyclic = copy.deepcopy(direct)
        loop = {}
        loop["self"] = loop
        cyclic["input"]["bundle"]["claims"][0]["metadata"] = loop
        self.assertEqual("error", execute_once(cyclic, self.document))

    def test_selector_branches_follow_exact_selector_authorized(self):
        # passingOtherScheme keeps presence authorization for a group that
        # also admits the selector scheme through verification.
        _, laundering = self._case_evaluation(
            "vet-control-key-verified-selector-laundering-reject"
        )
        _, proxy_case = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        lei_result = copy.deepcopy(proxy_case["input"]["resolvedResults"][0])
        other = copy.deepcopy(laundering)
        other["input"]["bundle"]["claims"].append({
            "ref": "lei:" + lei_result["artifact"]["identifier"],
            "issuedAt": other["input"]["bundle"]["presentedAt"],
            "verifiedBy": copy.deepcopy(lei_result["ref"]),
        })
        presenter = fixture_private_key("presenter")
        other["input"]["bundle"] = resign_bundle(
            other["input"]["bundle"], presenter, public_ref(presenter)
        )
        other["input"]["resolvedResults"].append(lei_result)
        other["input"]["requirement"] = {
            "requirementVersion": "1",
            "primaryClaimSelector": "key",
            "required": [{"scheme": "key", "verificationRequired": False}],
            "oneOf": [[
                {"scheme": "key", "verificationRequired": True, "recipeVersion": 1},
                {"scheme": "lei", "verificationRequired": True, "recipeVersion": 1},
            ]],
        }
        self.assertEqual("pass", execute_once(other, self.document))

        # A presence selector member that appears only inside oneOf.
        _, accept = self._case_evaluation("vet-control-key-presentation-accept")
        oneof_presence = copy.deepcopy(accept)
        oneof_presence["input"]["requirement"] = {
            "requirementVersion": "1", "primaryClaimSelector": "key",
            "required": [], "oneOf": [[{"scheme": "key", "verificationRequired": False}]],
        }
        self.assertEqual("pass", execute_once(oneof_presence, self.document))

        # The VC holder controller is compared by CF-3 identity.
        _, verified = self._case_evaluation("vet-ma3-verified-accept")
        document = copy.deepcopy(self.document)
        controller = copy.deepcopy(verified)
        controller = rebuild_direct_result(
            controller, document,
            lambda a: a["data"]["holderBinding"].update(
                controller=a["data"]["holderBinding"]["controller"] + "?role=holder"
            ),
        )
        self.assertTrue(execute_once(controller, document))

    def test_verified_selector_uses_the_reference_version_not_latest(self):
        # The exact claim's evidence is checked at its referenced recipe
        # version; a newer non-live family version does not disqualify it.
        _, evaluation = self._case_evaluation("vet-ma3-verified-accept")
        artifact = evaluation["input"]["resolvedResults"][0]["artifact"]
        family = (artifact["scheme"], artifact["method"], artifact["recipeVersion"])
        document = copy.deepcopy(self.document)
        context = document["trustedContext"]
        base = next(
            recipe for recipe in context["recipeRegistry"]["recipes"]
            if (recipe["scheme"], recipe["defaultMethod"]["kind"], recipe["recipeVersion"]) == family
        )
        later = copy.deepcopy(base)
        later["recipeVersion"] = 3
        later["availability"] = "disabled"
        unsigned = {k: v for k, v in later.items() if k != "signature"}
        later["signature"]["value"] = b64url_encode(
            fixture_private_key("recipe-steward").sign(
                (RECIPE_DOMAIN + hash_hex(unsigned)).encode("ascii")
            )
        )
        context["recipeRegistry"]["recipes"].append(later)
        append_recipe_authorities(context, later)
        self.assertIsNotNone(authenticated_result_context(
            document, authenticated_recipe_registry(document)
        ))
        self.assertEqual(
            family[2], evaluation["input"]["requirement"]["required"][0]["recipeVersion"]
        )
        self.assertTrue(execute_once(evaluation, document))

    def test_omitted_valid_until_uses_the_exact_not_latest_recipe_window(self):
        # A later recipe version with a wider default must not widen a
        # result validated under the earlier exact version (DACS-1 §6.3.2).
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        now = self.document["trustedContext"]["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]["trustedNow"]
        artifact = evaluation["input"]["resolvedResults"][0]["artifact"]
        family = (artifact["scheme"], artifact["method"], artifact["recipeVersion"])
        document = copy.deepcopy(self.document)
        context = document["trustedContext"]
        base = next(
            recipe for recipe in context["recipeRegistry"]["recipes"]
            if (recipe["scheme"], recipe["defaultMethod"]["kind"], recipe["recipeVersion"]) == family
        )
        later = copy.deepcopy(base)
        later["recipeVersion"] = 3
        later["defaultMaxAgeSec"] = base["defaultMaxAgeSec"] * 10
        unsigned = {k: v for k, v in later.items() if k != "signature"}
        later["signature"]["value"] = b64url_encode(
            fixture_private_key("recipe-steward").sign(
                (RECIPE_DOMAIN + hash_hex(unsigned)).encode("ascii")
            )
        )
        context["recipeRegistry"]["recipes"].append(later)
        append_recipe_authorities(context, later)
        self.assertIsNotNone(authenticated_result_context(
            document, authenticated_recipe_registry(document)
        ))
        age = base["defaultMaxAgeSec"] * 1_000 + 1
        changed = rebuild_direct_result(
            evaluation, document,
            lambda a: (a.pop("validUntil"), a.update(verifiedAt=now - age, fetchedAt=now - age)),
        )
        self.assertEqual(1, changed["input"]["requirement"]["required"][0]["recipeVersion"])
        self.assertEqual("fail", execute_once(changed, document))

    def test_verify_result_version_is_refused_not_reinterpreted(self):
        case, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        document = copy.deepcopy(self.document)
        control = rebuild_direct_result(evaluation, document, lambda a: None)
        self.assertEqual(case["expectedOutput"], execute_once(control, document))
        for version in ("2", 1, None):
            with self.subTest(resultVersion=version):
                document = copy.deepcopy(self.document)
                changed = rebuild_direct_result(
                    evaluation, document, lambda a: a.update(resultVersion=version)
                )
                self.assertEqual("error", execute_once(changed, document))

    def test_omitted_valid_until_uses_the_exact_recipe_default_window(self):
        case, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        self.assertEqual("pass", case["expectedOutput"])
        now = self.document["trustedContext"]["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]["trustedNow"]
        artifact = evaluation["input"]["resolvedResults"][0]["artifact"]
        default_ms = self.recipes[
            (artifact["scheme"], artifact["method"], artifact["recipeVersion"])
        ]["defaultMaxAgeSec"] * 1_000
        for age, expected in ((default_ms, "pass"), (default_ms + 1, "fail")):
            with self.subTest(age=age):
                document = copy.deepcopy(self.document)
                changed = rebuild_direct_result(
                    evaluation,
                    document,
                    lambda a, age=age: (
                        a.pop("validUntil"),
                        a.update(verifiedAt=now - age, fetchedAt=now - age),
                    ),
                )
                self.assertEqual(expected, execute_once(changed, document))

    def test_recipe_default_window_must_be_an_authenticated_safe_integer(self):
        # defaultMaxAgeSec is the fallback freshness authority; a signed
        # recipe carrying a malformed value invalidates the registry snapshot.
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        steward = fixture_private_key("recipe-steward")
        for malformed in ("300", -1, 300.5, None):
            with self.subTest(defaultMaxAgeSec=malformed):
                document = copy.deepcopy(self.document)
                recipe = document["trustedContext"]["recipeRegistry"]["recipes"][0]
                recipe["defaultMaxAgeSec"] = malformed
                unsigned = {k: v for k, v in recipe.items() if k != "signature"}
                recipe["signature"]["value"] = b64url_encode(
                    steward.sign((RECIPE_DOMAIN + hash_hex(unsigned)).encode("ascii"))
                )
                self.assertIsNone(authenticated_recipe_registry(document))
                self.assertEqual("error", execute_once(evaluation, document))

    def test_freshness_max_age_and_result_time_boundaries_are_exact(self):
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        now = self.document["trustedContext"]["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]["trustedNow"]

        def replay(mutate_artifact, max_age=None):
            document = copy.deepcopy(self.document)
            changed = rebuild_direct_result(evaluation, document, mutate_artifact)
            if max_age is not None:
                changed["input"]["requirement"]["required"][0]["maxAge"] = max_age
            return execute_once(changed, document)

        at = lambda t: (lambda a: a.update(verifiedAt=t, fetchedAt=t))
        # maxAge applicability is inclusive: decisionTime <= verifiedAt + maxAge*1000.
        self.assertEqual("pass", replay(at(now - 60_000), max_age=60))
        self.assertEqual("fail", replay(at(now - 60_001), max_age=60))
        self.assertEqual("pass", replay(at(now), max_age=0))
        self.assertEqual("fail", replay(at(now - 1), max_age=0))
        self.assertEqual("pass", replay(at(now - 500), max_age=0.5))
        self.assertEqual("fail", replay(at(now - 501), max_age=0.5))
        # Result validity is inclusive at validUntil.
        self.assertEqual("pass", replay(lambda a: a.update(validUntil=now)))
        self.assertEqual("fail", replay(lambda a: a.update(validUntil=now - 1)))
        # A result from the future, or with inverted internal times, errors.
        self.assertEqual("error", replay(at(now + 1)))
        self.assertEqual(
            "error", replay(lambda a: a.update(fetchedAt=a["verifiedAt"] + 1))
        )
        # DACS-1 §6.3.2: validUntil < verifiedAt is an undeterminable window,
        # which is stale for verified use rather than malformed input.
        self.assertEqual(
            "fail", replay(lambda a: a.update(validUntil=a["verifiedAt"] - 1))
        )
        # Inverted even when both times are ahead of the decision time: stale,
        # not the "future result" error.
        self.assertEqual("fail", replay(lambda a: a.update(
            fetchedAt=now + 10, verifiedAt=now + 10, validUntil=now + 5,
        )))

    def test_presence_member_parameters_and_mode_boundary(self):
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        presenter = fixture_private_key("presenter")

        def replay(member, metadata=None):
            changed = copy.deepcopy(evaluation)
            bundle = changed["input"]["bundle"]
            if metadata is not None:
                claim = next(c for c in bundle["claims"] if c["ref"].startswith("lei:"))
                claim["metadata"] = metadata
                changed["input"]["bundle"] = resign_bundle(
                    bundle, presenter, public_ref(presenter)
                )
            changed["input"]["requirement"] = {
                "requirementVersion": "1", "required": [member],
            }
            return execute_once(changed, self.document)

        member = {
            "scheme": "lei", "verificationRequired": False,
            "parameters": {"jurisdiction": "US"},
        }
        self.assertEqual("pass", replay(member, {"jurisdiction": "US"}))
        self.assertEqual("fail", replay(member, {"jurisdiction": "GB"}))
        self.assertEqual("fail", replay(member, {}))
        for extra in ({"maxAge": 60}, {"recipeVersion": 1}):
            with self.subTest(extra=extra):
                self.assertEqual(
                    "error", replay({**member, **extra}, {"jurisdiction": "US"})
                )

    def test_issuer_allow_list_is_load_bearing_for_credential_results(self):
        case, evaluation = self._case_evaluation("vet-ma3-verified-accept")
        self.assertTrue(case["expectedOutput"])
        steward = fixture_private_key("recipe-steward")
        document = copy.deepcopy(self.document)
        for recipe in document["trustedContext"]["recipeRegistry"]["recipes"]:
            if recipe["defaultMethod"]["kind"] != "verifiable-credential":
                continue
            recipe["defaultMethod"]["issuerAllowList"] = [
                public_ref(fixture_private_key("replacement-signer"))
            ]
            unsigned = {k: v for k, v in recipe.items() if k != "signature"}
            recipe["signature"]["value"] = b64url_encode(
                steward.sign((RECIPE_DOMAIN + hash_hex(unsigned)).encode("ascii"))
            )
        self.assertIsNotNone(authenticated_recipe_registry(document))
        self.assertFalse(execute_once(evaluation, document))

    def test_nonce_issuance_and_invocation_bindings_are_load_bearing(self):
        _, evaluation = self._case_evaluation("vet-ma3-verified-accept")
        self.assertTrue(execute_once(evaluation, self.document))
        invocation_id = evaluation["input"]["authority"]["invocation"]

        def issuance_of(document):
            context = document["trustedContext"]["vetInvocations"][invocation_id]
            return context, next(
                item for item in document["trustedContext"]["nonceIssuances"]
                if item["challengeId"] == context["challengeId"]
            )

        def other_party(context, issuance):
            other = public_ref(fixture_private_key("replacement-signer"))
            context["evaluatedParty"] = other
            issuance["evaluatedParty"] = other

        for label, mutate in (
            ("issuance attempt", lambda c, i: i.update(attempt=i["attempt"] + 1)),
            ("issuance phase", lambda c, i: i.update(phaseIndex=i["phaseIndex"] + 1)),
            ("primary claim is not the evaluated party", other_party),
        ):
            with self.subTest(label=label):
                document = copy.deepcopy(self.document)
                mutate(*issuance_of(document))
                self.assertFalse(execute_once(evaluation, document))

    # -- Test-audit regressions: each guard is isolated from earlier rejections. --

    def _direct_outcome(self, evaluation, document):
        """Complete direct (decision, reasons) through verifier-owned admission."""

        runtime = VetReferenceRuntime(document["trustedContext"])
        admitted, _ = runtime.admit_synthetic_test_input(evaluation)
        value = admitted["input"]
        admission = runtime.admit(value["authority"], value["bundle"])
        self.assertIsNotNone(admission)
        recipes = authenticated_recipe_registry(document)
        result_context = authenticated_result_context(document, recipes)
        self.assertIsNotNone(recipes)
        self.assertIsNotNone(result_context)
        return evaluate(
            value, recipes, result_context,
            decision_time=admission.trusted_now, admission=admission,
        )

    def _with_later_family_version(self, availability):
        document = copy.deepcopy(self.document)
        context = document["trustedContext"]
        base = next(
            recipe for recipe in context["recipeRegistry"]["recipes"]
            if (recipe["scheme"], recipe["defaultMethod"]["kind"], recipe["recipeVersion"])
            == ("lei", "consensus-backed-proxy", 1)
        )
        later = copy.deepcopy(base)
        later["recipeVersion"] = 3
        later["availability"] = availability
        resign_recipe(later)
        context["recipeRegistry"]["recipes"].append(later)
        append_recipe_authorities(context, later)
        return document

    def test_implicit_latest_must_be_live_without_older_fallback(self):
        # DACS-2 CRQ-2: "If the implicit latest entry is not live, aggregation
        # returns error and MUST NOT fall back to an older live version."  An
        # explicit pin to the older live version is unaffected.
        case, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        self.assertEqual("pass", case["expectedOutput"])
        self.assertEqual(1, evaluation["input"]["requirement"]["required"][0]["recipeVersion"])
        implicit = copy.deepcopy(evaluation)
        implicit["input"]["requirement"]["required"][0].pop("recipeVersion")
        # Control: the implicit latest is the live v1 that produced the result.
        self.assertEqual(("pass", []), self._direct_outcome(implicit, self.document))
        # Control: a later live version is selected; the v1 result does not
        # participate, so the member is unsatisfied rather than errored.
        live = self._with_later_family_version("live")
        self.assertEqual(
            ("fail", ["required failing or absent: lei"]),
            self._direct_outcome(implicit, live),
        )
        for availability in (
            "operator_gated", "closed_data", "bilateral", "mocked", "disabled", "failed",
        ):
            with self.subTest(availability=availability):
                document = self._with_later_family_version(availability)
                self.assertEqual(
                    ("error", ["unresolved recipe family or version"]),
                    self._direct_outcome(implicit, document),
                )
                self.assertEqual(
                    ("pass", []), self._direct_outcome(evaluation, document)
                )

    def test_explicit_non_operational_recipe_version_errors(self):
        # DACS-2 RAV-3: results from disabled, failed or mocked recipes are
        # error; operator-gated, closed-data and bilateral are not forced to
        # error.  Only the signed recipe availability changes.
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        for availability, expected in (
            ("live", ("pass", [])),
            ("operator_gated", ("pass", [])),
            ("closed_data", ("pass", [])),
            ("bilateral", ("pass", [])),
            ("mocked", ("error", ["unresolved recipe family or version"])),
            ("disabled", ("error", ["unresolved recipe family or version"])),
            ("failed", ("error", ["unresolved recipe family or version"])),
        ):
            with self.subTest(availability=availability):
                document = copy.deepcopy(self.document)
                recipe = next(
                    item for item in document["trustedContext"]["recipeRegistry"]["recipes"]
                    if item["scheme"] == "lei" and item["recipeVersion"] == 1
                )
                recipe["availability"] = availability
                resign_recipe(recipe)
                self.assertEqual(expected, self._direct_outcome(evaluation, document))

    def test_issuance_party_and_boolean_pins_are_isolated_guards(self):
        _, evaluation = self._case_evaluation("vet-ma3-verified-accept")
        self.assertIs(True, execute_once(evaluation, self.document))
        value = evaluation["input"]
        invocation_id = value["authority"]["invocation"]

        def issuance_of(document):
            context = document["trustedContext"]["vetInvocations"][invocation_id]
            return context, next(
                item for item in document["trustedContext"]["nonceIssuances"]
                if item["challengeId"] == context["challengeId"]
            )

        # Only the issuer-owned ledger record names another evaluated party;
        # the invocation context and presentation are unchanged.  The exact
        # nonce is still consumed by the attempt.
        document = copy.deepcopy(self.document)
        context, issuance = issuance_of(document)
        issuance["evaluatedParty"] = public_ref(fixture_private_key("replacement-signer"))
        runtime = VetReferenceRuntime(document["trustedContext"])
        self.assertIsNone(runtime.admit(value["authority"], value["bundle"]))
        self.assertTrue(runtime.nonce_ledger.consumed(context["challengeId"]))
        self.assertIs(False, execute_once(evaluation, document))

        # A JSON boolean that equals the pinned integer under host equality
        # (False == 0, True == 1) is still not an integer, so no later
        # issuance comparison can be the rejecting check.
        for field, boolean in (("phaseIndex", False), ("attempt", True)):
            with self.subTest(invocation_field=field):
                document = copy.deepcopy(self.document)
                context, issuance = issuance_of(document)
                self.assertEqual(issuance[field], boolean)
                context[field] = boolean
                self.assertIs(False, execute_once(evaluation, document))
            with self.subTest(issuance_field=field):
                _, issuance = issuance_of(copy.deepcopy(self.document))
                issuance[field] = boolean
                with self.assertRaisesRegex(ValueError, "not an exact safe integer"):
                    NonceLedger([issuance], registered_schemes=KNOWN_SCHEMES)

    def test_verifier_identity_issuance_authority_and_party_are_bound(self):
        case, evaluation = self._case_evaluation("vet-oneof-indeterminate-over-fail")
        self.assertEqual(case["expectedOutput"], execute_once(evaluation, self.document))
        invocation = self.document["trustedContext"]["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]
        other = public_ref(fixture_private_key("replacement-signer"))
        for label, mutate in (
            ("issuer is not the phase orchestrator",
             lambda item: item.update(issuedBy=other, expectedVerifier=other)),
            ("issued to another party", lambda item: item.update(evaluatedParty=other)),
        ):
            with self.subTest(label=label):
                document = copy.deepcopy(self.document)
                issuance = next(
                    item for item in document["trustedContext"]["nonceIssuances"]
                    if item["challengeId"] == invocation["verifierIdentityChallengeId"]
                )
                mutate(issuance)
                self.assertEqual(
                    {"decision": "error", "reasons": ["aggregation authority invalid"]},
                    execute_once(evaluation, document),
                )

    def test_session_context_must_canonically_equal_the_authenticated_session(self):
        # DACS-2 CRQ-1: VetCredentialsInput.sessionContext MUST be the
        # orchestrator-owned active context.  Equality is canonical JSON
        # equality: an integral-float spelling is the same value, while a
        # JSON boolean or an additional member is a different context.
        case, evaluation = self._case_evaluation("vet-oneof-indeterminate-over-fail")
        self.assertEqual(case["expectedOutput"], execute_once(evaluation, self.document))
        invalid = {"decision": "error", "reasons": ["aggregation authority invalid"]}
        for label, mutate, expected in (
            ("integral float pin",
             lambda item: item.update(recipeRegistryVersion=1.0), case["expectedOutput"]),
            ("boolean pin", lambda item: item.update(recipeRegistryVersion=True), invalid),
            ("additional member", lambda item: item.update(sessionState="vet-pending"), invalid),
        ):
            with self.subTest(label=label):
                changed = copy.deepcopy(evaluation)
                mutate(changed["input"]["authority"]["vetInput"]["sessionContext"])
                self.assertEqual(expected, execute_once(changed, self.document))

    def test_authenticated_artifact_hash_and_source_family_are_load_bearing(self):
        # The fixture resolver binds the complete serialized result hash in
        # addition to the signature-excluded reference hash, and the source
        # attestation to the result's exact signed family.
        _, evaluation = self._case_evaluation(
            "vet-control-existence-only-lei-supporting-context"
        )
        resolved = evaluation["input"]["resolvedResults"][0]
        self.assertEqual("consensus-backed-proxy", resolved["artifact"]["method"])
        self.assertTrue(verify_result(resolved, self.recipes, self.result_context))

        trust = copy.deepcopy(self.result_context)
        trust["resultHashByRef"][canonical_bytes(resolved["ref"])] = "00" * 32
        self.assertFalse(verify_result(resolved, self.recipes, trust))

        document = copy.deepcopy(self.document)
        entry = next(
            item for item in document["trustedContext"]["authenticatedSourceAttestations"]
            if canonical_bytes(item["attestation"])
            == canonical_bytes(resolved["artifact"]["attestation"])
        )
        # Another method of the same authenticated owner family.
        entry["method"] = "tlsnotary"
        context = authenticated_result_context(
            document, authenticated_recipe_registry(document)
        )
        self.assertIsNotNone(context)
        self.assertFalse(verify_result(resolved, self.recipes, context))

    def test_exact_nonce_is_consumed_even_when_expired(self):
        # CORE SN-4: an attempt carrying the issued nonce is consumed before
        # validation, including when the bounded lifetime has elapsed.  The
        # lifetime is inclusive at expiresAt.
        _, evaluation = self._case_evaluation("vet-ma3-verified-accept")
        value = evaluation["input"]
        invocation_id = value["authority"]["invocation"]
        for offset, admitted in ((0, True), (1, False)):
            with self.subTest(after_expiry_ms=offset):
                document = copy.deepcopy(self.document)
                context = document["trustedContext"]["vetInvocations"][invocation_id]
                issuance = next(
                    item for item in document["trustedContext"]["nonceIssuances"]
                    if item["challengeId"] == context["challengeId"]
                )
                context["trustedNow"] = issuance["expiresAt"] + offset
                runtime = VetReferenceRuntime(document["trustedContext"])
                admission = runtime.admit(value["authority"], value["bundle"])
                self.assertEqual(admitted, admission is not None)
                self.assertTrue(runtime.nonce_ledger.consumed(context["challengeId"]))

    def test_presented_by_must_resolve_to_a_signed_bundle_claim(self):
        # DACS-1 §6.3.2 presentedBy selection rule: presentedBy "MUST be one of
        # the claim references appearing in claims" and its exact control must
        # be proven.  Claim membership and a cosigner therefore establish only
        # a structurally valid bundle, not control of the declared presenter.
        case, evaluation = self._case_evaluation("vet-control-key-presentation-accept")
        self.assertEqual("pass", case["expectedOutput"])
        presented = evaluation["input"]["bundle"]["presentedBy"]
        presenter = fixture_private_key("presenter")
        self.assertEqual(presented, public_ref(presenter))
        cosigner = fixture_private_key("bundle-cosigner")
        cosigner_ref = public_ref(cosigner)
        selector_requirement = evaluation["input"]["requirement"]
        self.assertEqual("key", selector_requirement["primaryClaimSelector"])
        presence_requirement = {
            "requirementVersion": "1",
            "required": [{"scheme": "key", "verificationRequired": False}],
        }

        def variant(
            claim_refs, requirement, operation="decision", *,
            signer=presenter, signer_ref=presented,
        ):
            changed = copy.deepcopy(evaluation)
            changed["operation"] = operation
            bundle = changed["input"]["bundle"]
            bundle["claims"] = [
                {"ref": ref, "issuedAt": 1_899_999_999_000} for ref in claim_refs
            ]
            changed["input"]["bundle"] = resign_bundle(
                bundle, signer, signer_ref
            )
            changed["input"]["requirement"] = copy.deepcopy(requirement)
            return changed

        # Controls: presentedBy resolves exactly, or by CF-3 identity to a
        # parameterised reference of the same key.
        for label, refs in (
            ("exact", [presented, cosigner_ref]),
            ("CF-3 identity", [presented + "?role=holder", cosigner_ref]),
        ):
            with self.subTest(control=label):
                signer_ref = refs[0]
                accepted = variant(
                    refs, presence_requirement, signer_ref=signer_ref
                )
                self.assertIs(True, verify_bundle(accepted["input"]["bundle"]))
                self.assertEqual(
                    ("pass", []), self._direct_outcome(accepted, self.document)
                )

        # The sole claim, signature ref, and presentedBy may use three distinct
        # CF-2 parameter spellings while sharing one CF-3 key identity. This
        # exercises both verifier-owned admission and the external JSON entry.
        distinct_qualifiers = variant(
            [presented + "?purpose=session"],
            presence_requirement,
            signer_ref=presented + "?role=holder",
        )
        distinct_bundle = distinct_qualifiers["input"]["bundle"]
        self.assertEqual(1, len(distinct_bundle["claims"]))
        self.assertNotEqual(
            distinct_bundle["claims"][0]["ref"],
            distinct_bundle["presentation"]["signatures"][0]["ref"],
        )
        self.assertIs(True, verify_bundle(distinct_bundle))
        self.assertEqual(
            ("pass", []),
            self._direct_outcome(distinct_qualifiers, self.document),
        )
        raw = json.dumps(
            distinct_qualifiers, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertEqual(
            "pass", execute_external_once(raw, self.document)
        )

        cosigned_only = variant(
            [presented, cosigner_ref],
            presence_requirement,
            signer=cosigner,
            signer_ref=cosigner_ref,
        )
        self.assertIs(True, verify_bundle(cosigned_only["input"]["bundle"]))
        self.assertEqual(
            ("fail", ["presentedBy is uncontrolled"]),
            self._direct_outcome(cosigned_only, self.document),
        )
        selector_cosigned_only = variant(
            [presented, cosigner_ref],
            selector_requirement,
            signer=cosigner,
            signer_ref=cosigner_ref,
        )
        self.assertEqual(
            (
                "fail",
                [
                    "primaryClaimSelector is mismatched, uncontrolled, or unauthorized"
                ],
            ),
            self._direct_outcome(selector_cosigned_only, self.document),
        )

        # Zero presenter matches is a semantic non-match once another included
        # claim supplies a valid bundle signature.  Exercise every public
        # direct operation and the exact received-JSON boundary with and
        # without a selector.
        for label, requirement, direct_expected in (
            (
                "no selector",
                presence_requirement,
                ("fail", ["presentedBy is uncontrolled"]),
            ),
            (
                "selector",
                selector_requirement,
                (
                    "fail",
                    [
                        "primaryClaimSelector is mismatched, uncontrolled, or unauthorized"
                    ],
                ),
            ),
        ):
            with self.subTest(absent_presenter=label):
                missing = variant(
                    [cosigner_ref], requirement,
                    signer=cosigner, signer_ref=cosigner_ref,
                )
                bundle = missing["input"]["bundle"]
                self.assertEqual(presented, bundle["presentedBy"])
                self.assertEqual(
                    evaluation["input"]["bundle"]["sessionNonce"],
                    bundle["sessionNonce"],
                )
                self.assertIs(True, verify_bundle(bundle))
                self.assertIsNone(presented_claim(bundle))
                self.assertEqual(
                    direct_expected, self._direct_outcome(missing, self.document)
                )
                for operation, expected in (
                    ("decision", "fail"),
                    ("control-decision", "fail"),
                    ("match", False),
                ):
                    with self.subTest(operation=operation):
                        candidate = variant(
                            [cosigner_ref], requirement, operation,
                            signer=cosigner, signer_ref=cosigner_ref,
                        )
                        self.assertEqual(
                            expected, execute_once(candidate, self.document)
                        )
                        raw = json.dumps(
                            candidate, sort_keys=True, separators=(",", ":")
                        ).encode("utf-8")
                        self.assertEqual(
                            expected, execute_external_once(raw, self.document)
                        )

        # Admission still consumes the issued nonce for the authenticated
        # semantic failure.
        missing = variant(
            [cosigner_ref], presence_requirement,
            signer=cosigner, signer_ref=cosigner_ref,
        )
        runtime = VetReferenceRuntime(self.document["trustedContext"])
        admitted, capability = runtime.admit_synthetic_test_input(missing)
        invocation_id = admitted["input"]["authority"]["invocation"]
        challenge_id = runtime.invocations[invocation_id]["challengeId"]
        self.assertEqual(
            "fail",
            execute(admitted, self.document, runtime, capability),
        )
        self.assertTrue(runtime.nonce_ledger.consumed(challenge_id))

        # A signature by a key absent from claims remains a structural error;
        # it is not the otherwise-valid semantic boundary above.
        missing_signer_membership = variant([cosigner_ref], presence_requirement)
        self.assertIs(False, verify_bundle(
            missing_signer_membership["input"]["bundle"]
        ))
        self.assertEqual(
            ("error", ["invalid identity bundle"]),
            self._direct_outcome(missing_signer_membership, self.document),
        )

    def test_authenticated_absent_presenter_is_fail_in_current_and_historical_aggregate(self):
        # Keep the two committed verification results and receipt authentic.
        # Only replace the key presenter claim with an included cosigner, then
        # re-sign the bundle and its bound record/receipt.
        _, source = self._case_evaluation("vet-cross-accumulator-fail-over-error")
        document = copy.deepcopy(self.document)
        candidate = copy.deepcopy(source)
        value = candidate["input"]
        vet_input = value["authority"]["vetInput"]
        bundle = vet_input["bundleToVet"]
        presented = bundle["presentedBy"]
        cosigner = fixture_private_key("bundle-cosigner")
        cosigner_ref = public_ref(cosigner)
        bundle["claims"] = [
            item for item in bundle["claims"] if item["ref"] != presented
        ] + [{"ref": cosigner_ref, "issuedAt": 1_899_999_999_000}]
        bundle = resign_bundle(bundle, cosigner, cosigner_ref)
        vet_input["bundleToVet"] = bundle
        value["record"]["bundleHash"] = hash_hex({
            key: item for key, item in bundle.items() if key != "presentation"
        })
        candidate["input"] = reanchor_composite_input(value, document)

        self.assertTrue(verify_bundle(bundle))
        self.assertIsNone(presented_claim(bundle))
        expected = {
            "decision": "fail",
            "reasons": [
                "presentedBy is uncontrolled",
                "required failing or absent: lei",
            ],
        }
        self.assertEqual(expected, execute_once(candidate, document))
        self.assertEqual(expected, reconstruct_historical_once(candidate, document))
        raw = json.dumps(
            candidate, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertEqual(expected, execute_external_once(raw, document))

    def test_golden_generator_uses_cf3_signer_membership(self):
        spec = importlib.util.spec_from_file_location(
            "generate_dacs1_vet_golden_inputs_under_test", GENERATOR
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)

        claim_ref = generator.PRESENTER_REF + "?purpose=session"
        signer_ref = generator.PRESENTER_REF + "?role=holder"
        bundle = generator.signed_bundle(
            [generator.claim(claim_ref, issuedAt=generator.NOW - 1_000)],
            presented_by=generator.PRESENTER_REF,
            signer_ref=signer_ref,
        )
        self.assertEqual([claim_ref], [item["ref"] for item in bundle["claims"]])
        self.assertEqual(
            [signer_ref],
            [item["ref"] for item in bundle["presentation"]["signatures"]],
        )
        _, _, rebound = generator.begin_invocation(bundle)
        self.assertEqual([claim_ref], [item["ref"] for item in rebound["claims"]])
        self.assertEqual(
            [signer_ref],
            [item["ref"] for item in rebound["presentation"]["signatures"]],
        )


if __name__ == "__main__":
    unittest.main()
