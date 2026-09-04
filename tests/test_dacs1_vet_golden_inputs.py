import base64
import copy
import hashlib
import ipaddress
import json
import math
import re
import subprocess
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

import idna
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


ROOT = Path(__file__).resolve().parents[1]
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
KEY = re.compile(r"^[0-9a-f]{64}$")
LEI = re.compile(r"^[0-9A-Z]{20}$")
FINRA_CRD = re.compile(r"^[1-9][0-9]*$")
DID_IDENTIFIER = re.compile(
    r"^[a-z0-9]+:[A-Za-z0-9._:%-]+(?::[A-Za-z0-9._:%-]+)*$"
)
SAFE_INT = 9_007_199_254_740_991


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


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def hash_hex(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


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
    if (
        not isinstance(value, str)
        or value != unicodedata.normalize("NFC", value)
        or ":" not in value
    ):
        raise ValueError("malformed ClaimReference")
    scheme, identifier = value.split(":", 1)
    if scheme not in KNOWN_SCHEMES or not identifier:
        raise ValueError("unknown or empty ClaimReference")
    if scheme == "key" and not KEY.fullmatch(identifier):
        raise ValueError("key identifiers are 32-byte lowercase hex")
    if scheme in {"lei", "cci-lei"} and not LEI.fullmatch(identifier):
        raise ValueError("LEI identifiers are exactly 20 uppercase alphanumerics")
    if scheme == "finra-crd" and not FINRA_CRD.fullmatch(identifier):
        raise ValueError("FINRA CRD identifiers are canonical positive decimals")
    if scheme == "did" and not DID_IDENTIFIER.fullmatch(identifier):
        raise ValueError("DID identifier is not canonical")
    if scheme == "domain":
        try:
            if (
                not identifier.isascii()
                or identifier != identifier.lower()
                or identifier.endswith(".")
                or idna.encode(
                    identifier, uts46=False, std3_rules=True
                ).decode("ascii") != identifier
            ):
                raise ValueError("domain identifier is not canonical")
        except (idna.IDNAError, UnicodeError, ValueError) as error:
            raise ValueError("domain identifier is not canonical") from error
        try:
            ipaddress.ip_address(identifier)
        except ValueError:
            pass
        else:
            raise ValueError("IP literals are not domain identifiers")
    return scheme, identifier


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
            or recipe.get("availability") != "live"
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


def verify_bundle(bundle):
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
    if bundle.get("bundleVersion") != "1" or type(bundle.get("presentedAt")) is not int:
        return False
    claims = bundle.get("claims")
    if not isinstance(claims, list) or not claims:
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
    payload = (BUNDLE_DOMAIN + hash_hex(unsigned)).encode("ascii")
    claim_refs = {item["ref"] for item in claims}
    return all(
        isinstance(item, dict)
        and set(item) == {"ref", "signature"}
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
    } or signature.get("algorithm") != "ed25519":
        return False
    unsigned = {key: value for key, value in artifact.items() if key != "signature"}
    if hash_hex(unsigned) != reference["contentHash"]:
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
    full_hash = hash_hex(artifact)
    authenticated_full_hash = result_context["resultHashByRef"].get(
        canonical_bytes(reference)
    )
    source_attestation = result_context["attestationByKey"].get(
        canonical_bytes(artifact.get("attestation"))
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
    ):
        return False
    return verify_signature(
        authority["signer"],
        signature.get("value"),
        (RESULT_DOMAIN + hash_hex(unsigned)).encode("ascii"),
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


def matching_claims(value, req, exact_ref=None):
    now = value["evaluatedAt"]
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
        if parameters is not None:
            metadata = item.get("metadata")
            if not isinstance(metadata, dict) or any(
                metadata.get(key) != item for key, item in parameters.items()
            ):
                continue
        matches.append(item)
    return matches


def result_outcome(value, claim, req, recipes, result_context):
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
        or result.get("recipeVersion") != req.get("recipeVersion")
    ):
        return "fail"
    decision = result.get("decision")
    if decision not in {"pass", "fail", "indeterminate", "error"}:
        return "error"
    if decision != "pass":
        return decision
    verified_at = result.get("verifiedAt")
    valid_until = result.get("validUntil")
    if type(verified_at) is not int or type(valid_until) is not int:
        return "fail"
    now = value["evaluatedAt"]
    expires_at = claim.get("expiresAt")
    effective_expiry = min(
        valid_until,
        expires_at if type(expires_at) is int else SAFE_INT,
    )
    if valid_until < verified_at or now > effective_expiry:
        return "fail"
    max_age = req.get("maxAge")
    if max_age is not None and now > verified_at + max_age * 1_000:
        return "fail"
    return "pass"


def classify_member(value, req, recipes, result_context, exact_ref=None):
    matches = matching_claims(value, req, exact_ref)
    if req.get("verificationRequired") is False:
        return "pass" if matches else "fail"
    outcomes = [
        result_outcome(value, item, req, recipes, result_context)
        for item in matches
    ]
    for outcome in ("pass", "fail", "error", "indeterminate"):
        if outcome in outcomes:
            return outcome
    return "fail"


def presented_control(value, recipes, result_context):
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
        ) == "pass"
        and result.get("method") == "verifiable-credential"
        and isinstance(binding, dict)
        and binding.get("controller") in signer_refs
    )


def selector_authorized(value, req, recipes, result_context):
    selector = req.get("primaryClaimSelector")
    if selector is None:
        return True
    bundle = value["bundle"]
    scheme, _ = parse_ref(bundle["presentedBy"])
    if scheme != selector or not presented_control(
        value, recipes, result_context
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
            value, selected_req, recipes, result_context,
            exact_ref=bundle["presentedBy"]
        ) == "pass"
    presence_members = [
        item for item in required
        if item.get("scheme") == selector
        and item.get("verificationRequired") is False
    ]
    if any(
        classify_member(
            value, item, recipes, result_context,
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
                value, item, recipes, result_context,
                exact_ref=bundle["presentedBy"]
            ) == "pass"
            for item in group
        ):
            return True
    return False


def valid_requirement(req):
    if not isinstance(req, dict) or req.get("requirementVersion") != "1":
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
            or item.get("scheme") not in KNOWN_SCHEMES
            or type(item.get("verificationRequired")) is not bool
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


def evaluate(value, recipes, result_context):
    if not isinstance(value, dict) or type(value.get("evaluatedAt")) is not int:
        return "error", ["invalid evaluation time"]
    if not verify_bundle(value.get("bundle")):
        return "error", ["invalid identity bundle"]
    req = value.get("requirement")
    if not valid_requirement(req):
        return "error", ["invalid bundle requirement"]
    for item in value["bundle"]["claims"]:
        if "verifiedBy" in item and not well_formed_result_ref(item["verifiedBy"]):
            return "error", ["malformed verification reference"]
    if resolved_by_ref(value) is None:
        return "error", ["duplicate or malformed resolved result reference"]
    failures = []
    errors = []
    indeterminates = []
    for item in req.get("required", []):
        outcome = classify_member(value, item, recipes, result_context)
        if outcome == "fail":
            failures.append("required failing or absent: " + item["scheme"])
        elif outcome == "error":
            errors.append("required errored: " + item["scheme"])
        elif outcome == "indeterminate":
            indeterminates.append("required indeterminate: " + item["scheme"])
    for group in req.get("oneOf", []):
        outcomes = [
            classify_member(value, item, recipes, result_context)
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
    if not selector_authorized(value, req, recipes, result_context):
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


def evaluate_decision(value, recipes, result_context):
    return evaluate(value, recipes, result_context)[0]


def well_formed_record_ref(value):
    if not isinstance(value, dict) or set(value) != {
        "anchor", "contentHash", "signer"
    }:
        return False
    anchor = value.get("anchor")
    return (
        isinstance(anchor, dict)
        and set(anchor) == {"kind", "locator"}
        and anchor.get("kind") in {"storage-program", "ipfs", "https"}
        and isinstance(anchor.get("locator"), str)
        and bool(anchor["locator"])
        and isinstance(value.get("contentHash"), str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", value["contentHash"]))
        and isinstance(value.get("signer"), str)
    )


def authenticate_production_aggregate(
    value, trusted_context, recipes, result_context
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
        or authority.get("kind") != "production"
    ):
        return None
    signature = record.get("signature")
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "signer", "value"}
        or signature.get("algorithm") != "ed25519"
        or signature.get("signer") != record_ref.get("signer")
    ):
        return None
    unsigned_record = {
        key: item for key, item in record.items() if key != "signature"
    }
    record_hash = hash_hex(unsigned_record)
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
        sessions.get(session_name) if isinstance(sessions, dict) else None
    )
    if not isinstance(vet_input, dict) or not isinstance(authenticated_session, dict):
        return None
    session_context = vet_input.get("sessionContext")
    job_id = record.get("jobId")
    registry_version = authenticated_session.get("recipeRegistryVersion")
    if (
        not isinstance(session_context, dict)
        or canonical_bytes(session_context) != canonical_bytes(authenticated_session)
        or vet_input.get("jobId") != job_id
        or session_context.get("jobId") != job_id
        or vet_input.get("recipeRegistryVersion") != registry_version
        or trusted_context.get("recipeRegistry", {}).get(
            "recipeRegistryVersion"
        ) != registry_version
        or not isinstance(recipes, dict)
    ):
        return None

    bundle = vet_input.get("bundleToVet")
    req = vet_input.get("requirement")
    verifier_identity = vet_input.get("verifierIdentity")
    if (
        not verify_bundle(bundle)
        or not verify_bundle(verifier_identity)
        or signature.get("signer") != verifier_identity.get("presentedBy")
        or record.get("evaluatedParty") != bundle.get("presentedBy")
        or record.get("bundleHash")
        != hash_hex({key: item for key, item in bundle.items() if key != "presentation"})
        or record.get("requirementHash") != hash_hex(req)
    ):
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
    ):
        return None
    committed = committed + deal_specific
    resolved_refs = [item.get("ref") for item in resolved if isinstance(item, dict)]
    canonical_refs = [canonical_bytes(item) for item in committed]
    if (
        len(resolved_refs) != len(resolved)
        or [canonical_bytes(item) for item in resolved_refs] != canonical_refs
        or len(set(canonical_refs)) != len(canonical_refs)
        or any(
            not verify_result(item, recipes, result_context)
            for item in resolved
        )
    ):
        return None
    return {
        "evaluatedAt": value.get("evaluatedAt"),
        "bundle": bundle,
        "requirement": req,
        "resolvedResults": resolved,
    }


def aggregate_output(value, trusted_context, recipes, result_context):
    projection = authenticate_production_aggregate(
        value, trusted_context, recipes, result_context
    )
    if projection is None:
        return {"decision": "error", "reasons": ["aggregation authority invalid"]}
    decision, reasons = evaluate(projection, recipes, result_context)
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


def execute(evaluation, document):
    operation = evaluation["operation"]
    value = evaluation["input"]
    recipes = authenticated_recipe_registry(document)
    result_context = authenticated_result_context(document, recipes)
    if operation == "match":
        return evaluate_decision(value, recipes, result_context) == "pass"
    if operation == "decision":
        return evaluate_decision(value, recipes, result_context)
    if operation == "decision-no-throw":
        try:
            return {
                "decision": evaluate_decision(value, recipes, result_context),
                "throws": False,
            }
        except Exception:  # the vector explicitly proves this boundary
            return {"decision": "error", "throws": True}
    if operation == "control-decision":
        if not verify_bundle(value.get("bundle")):
            return "error"
        return (
            "pass"
            if presented_control(value, recipes, result_context)
            else "fail"
        )
    if operation == "aggregate":
        return aggregate_output(
            value, document["trustedContext"], recipes, result_context
        )
    raise AssertionError(f"unknown operation {operation!r}")


def execute_case(case, document):
    observed = {
        name: execute(evaluation, document)
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
        self.assertEqual(24, self.document["count"])
        self.assertEqual(24, len(self.cases))
        self.assertEqual(24, len({case["name"] for case in self.cases}))
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
        self.assertEqual(24, binding["caseCount"])
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
        self.assertEqual(case["expectedOutput"], execute(evaluation, self.document))
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
                execute(changed, self.document),
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
            case["expectedOutput"], execute(evaluation, self.document)
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
                self.assertEqual("error", execute(changed, self.document))

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
                self.assertEqual("error", execute(changed, self.document))

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
        self.assertFalse(execute(changed, self.document))

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
                "requirement": {
                    "requirementVersion": "1",
                    "required": [{
                        "scheme": "lei", "verificationRequired": False,
                    }],
                },
                "resolvedResults": [],
            },
        }
        self.assertFalse(execute(evaluation, self.document))

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
        self.assertNotEqual("pass", execute(changed, self.document))

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
