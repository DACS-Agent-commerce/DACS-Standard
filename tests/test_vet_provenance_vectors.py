"""Independent Vet-provenance oracle after baseline DACS-1 shape validation."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "vet-provenance-v0.6.json"

BASE_VECTOR_NAMES = (
    "ordinary-bilateral-third-party-verifiers",
    "procurement-two-bidder-completed",
)

LISTING_DOMAIN = "dacs-listing:v1:"
BUNDLE_DOMAIN = "dacs-bundle-presentation:v1:"
VERIFY_DOMAIN = "dacs-verifyresult:v1:"
LEGACY_COMPOSITE_DOMAIN = "dacs-composite:v1:"
AUTH_DOMAIN = "dacs-vet-authorization:v1:"
COMPOSITE_DOMAIN = "dacs-provenanced-composite:v1:"
RECEIPT_DOMAIN = "fixture-anchor-receipt:v1:"
RECEIPT_VALIDATOR = "key:e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58"
ROLE_ORDER = {"counterparty": 0, "publisher": 1}
FIXTURE_NOW = 1786723200000
RECIPE_REGISTRY_VERSION = 7
RAIL_REGISTRY_VERSION = 3
MAX_SAFE_INTEGER = 2**53 - 1
CANONICAL_POSITIVE_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?")
LISTING_ID = re.compile(r"[A-Za-z0-9._~-]{1,128}")


def canonical(value):
    # All fixture strings are ASCII; stdlib canonical JSON is byte-equal to JCS here.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hash_value(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def collection_hash(value):
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def decode_json_pointer(path):
    """Decode an RFC 6901 pointer, rejecting malformed escape sequences."""
    if not isinstance(path, str):
        raise ValueError("JSON Patch path must be a string")
    if path == "":
        return ()
    if not path.startswith("/"):
        raise ValueError("non-empty JSON Patch path must start with '/'")
    decoded = []
    for raw_token in path[1:].split("/"):
        token = []
        index = 0
        while index < len(raw_token):
            character = raw_token[index]
            if character != "~":
                token.append(character)
                index += 1
                continue
            if index + 1 >= len(raw_token) or raw_token[index + 1] not in "01":
                raise ValueError("invalid JSON Pointer escape")
            token.append("~" if raw_token[index + 1] == "0" else "/")
            index += 2
        decoded.append("".join(token))
    return tuple(decoded)


def array_index(token, length, *, allow_append):
    if allow_append and token == "-":
        return length
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", token):
        raise ValueError("invalid JSON Patch array index")
    index = int(token)
    maximum = length if allow_append else length - 1
    if index > maximum:
        raise ValueError("JSON Patch array index is out of bounds")
    return index


def strict_apply_patch(base, patch):
    """Apply the fixture's strict RFC 6902 add/remove/replace subset."""
    if not isinstance(patch, list):
        raise ValueError("JSON Patch must be an array")

    prepared = []
    paths = []
    for operation in patch:
        if not isinstance(operation, dict):
            raise ValueError("JSON Patch operation must be an object")
        kind = operation.get("op")
        if kind not in {"add", "remove", "replace"}:
            raise ValueError("unsupported JSON Patch operation")
        required = {"op", "path"} if kind == "remove" else {"op", "path", "value"}
        if set(operation) != required:
            raise ValueError("unexpected JSON Patch operation members")
        tokens = decode_json_pointer(operation["path"])
        for previous in paths:
            common = min(len(previous), len(tokens))
            if previous[:common] == tokens[:common]:
                raise ValueError("duplicate or overlapping JSON Patch paths")
        paths.append(tokens)
        prepared.append((operation, tokens))

    document = copy.deepcopy(base)
    for operation, tokens in prepared:
        kind = operation["op"]
        if not tokens:
            if kind == "remove":
                raise ValueError("fixture patches cannot remove the document root")
            document = copy.deepcopy(operation["value"])
            continue

        parent = document
        for token in tokens[:-1]:
            if isinstance(parent, dict):
                if token not in parent:
                    raise ValueError("JSON Patch parent member does not exist")
                parent = parent[token]
            elif isinstance(parent, list):
                parent = parent[array_index(token, len(parent), allow_append=False)]
            else:
                raise ValueError("JSON Patch path traverses a scalar")

        token = tokens[-1]
        if isinstance(parent, dict):
            if kind in {"remove", "replace"} and token not in parent:
                raise ValueError("JSON Patch target member does not exist")
            if kind == "remove":
                del parent[token]
            else:
                parent[token] = copy.deepcopy(operation["value"])
        elif isinstance(parent, list):
            index = array_index(token, len(parent), allow_append=kind == "add")
            if kind == "remove":
                del parent[index]
            elif kind == "add":
                parent.insert(index, copy.deepcopy(operation["value"]))
            else:
                parent[index] = copy.deepcopy(operation["value"])
        else:
            raise ValueError("JSON Patch target parent is a scalar")
    return document


def expand_compact_vectors(vectors):
    """Expand one-level fixture bases without sharing mutable input objects."""
    if not isinstance(vectors, list):
        raise ValueError("vectors must be an array")
    by_name = {}
    for vector in vectors:
        if not isinstance(vector, dict) or not isinstance(vector.get("name"), str):
            raise ValueError("every vector must be a named object")
        if vector["name"] in by_name:
            raise ValueError("duplicate vector name")
        by_name[vector["name"]] = vector

    literal_names = {item["name"] for item in vectors if "input" in item}
    if literal_names != set(BASE_VECTOR_NAMES):
        raise ValueError("the representation must contain exactly the two literal bases")
    for name in BASE_VECTOR_NAMES:
        base = by_name.get(name)
        if base is None or "base" in base or "patch" in base:
            raise ValueError("base vectors cannot recursively reference another base")

    expanded_vectors = []
    for vector in vectors:
        base_shape = {
            "name", "rule", "operation", "input", "expandedInputHash", "expected", "note"
        }
        patch_shape = {
            "name", "rule", "operation", "base", "patch", "expandedInputHash", "expected", "note"
        }
        if vector["name"] in BASE_VECTOR_NAMES:
            if set(vector) != base_shape:
                raise ValueError("literal base vector has unexpected members")
            expanded_input = copy.deepcopy(vector["input"])
        else:
            if set(vector) != patch_shape:
                raise ValueError("patch vector has unexpected members")
            base_name = vector["base"]
            if not isinstance(base_name, str):
                raise ValueError("patch vector base must be a string")
            base = by_name.get(base_name)
            if base_name not in BASE_VECTOR_NAMES or base is None:
                raise ValueError("patch vector references an unknown base")
            if "input" not in base or "base" in base or "patch" in base:
                raise ValueError("patch vector references a recursive base")
            expanded_input = strict_apply_patch(base["input"], vector["patch"])

        if not isinstance(expanded_input, dict):
            raise ValueError("expanded vector input must be an object")
        claimed_input_hash = vector.get("expandedInputHash")
        if not isinstance(claimed_input_hash, str) or not re.fullmatch(
            r"[0-9a-f]{64}", claimed_input_hash
        ):
            raise ValueError("expanded input hash must be lowercase sha256")
        if hash_value(expanded_input) != claimed_input_hash:
            raise ValueError("expanded input hash mismatch")

        semantic = {
            key: copy.deepcopy(value)
            for key, value in vector.items()
            if key not in {"base", "patch", "expandedInputHash", "input"}
        }
        semantic["input"] = expanded_input
        expanded_vectors.append(semantic)
    return expanded_vectors


def signing_hash(artifact, omitted):
    return hash_value({key: value for key, value in artifact.items() if key != omitted})


def full_hash(artifact):
    return hash_value(artifact)


def bundle_hash(bundle):
    return signing_hash(bundle, "presentation")


def cf4(value):
    return quote(value, safe="-._~")


def auth_logical(artifact):
    return (
        "dacs2:vet-authorization:"
        f"{artifact['jobId']}:{artifact['evaluatedRole']}:"
        f"{cf4(artifact['counterpartyContext'])}:{cf4(artifact['evaluatedParty'])}"
    )


def composite_logical(artifact):
    return (
        "dacs2:provenanced-composite:"
        f"{artifact['jobId']}:{artifact['evaluatedRole']}:"
        f"{cf4(artifact['counterpartyContext'])}:{cf4(artifact['evaluatedParty'])}"
    )


def ref_key(ref):
    return ref["anchor"]["locator"], ref["contentHash"]


def result_ref_key(ref):
    return ref["anchor"]["locator"], ref["contentHash"], ref["recipeVersion"]


def expected_vet_refs(case):
    items = []
    for kind_order, collection in enumerate((case["authorizations"], case["composites"])):
        for item in collection:
            artifact = item["artifact"]
            items.append(
                (
                    artifact["counterpartyContext"].encode("utf-8"),
                    ROLE_ORDER.get(artifact.get("evaluatedRole"), 99),
                    kind_order,
                    item["ref"],
                )
            )
    return [value[3] for value in sorted(items, key=lambda value: value[:3])]


class InvalidChain(Exception):
    pass


def require(condition, message):
    if not condition:
        raise InvalidChain(message)


def verify_positive_price(term, message):
    require(isinstance(term, dict), message)
    amount = term.get("amount")
    require(
        isinstance(amount, str)
        and CANONICAL_POSITIVE_DECIMAL.fullmatch(amount) is not None
        and any(character != "0" and character != "." for character in amount),
        message,
    )
    require(isinstance(term.get("currency"), str) and term["currency"], message)


def safe_integer(value, *, minimum=0):
    return type(value) is int and minimum <= value <= MAX_SAFE_INTEGER


def expected_session_context(case, listing_ref, prior_phase_outputs):
    publisher_role = "buyer" if case["mode"] == "procurement" else "seller"
    counterparty_role = "seller" if case["mode"] == "procurement" else "buyer"
    parties = [
        {
            "role": publisher_role,
            "bundleHash": bundle_hash(case["publisher"]),
            "primaryClaim": case["publisher"]["presentedBy"],
        }
    ]
    if case["mode"] != "procurement":
        parties.extend(
            {
                "role": counterparty_role,
                "bundleHash": bundle_hash(candidate),
                "primaryClaim": candidate["presentedBy"],
            }
            for candidate in case["candidates"]
        )
    return {
        "jobId": case["jobId"],
        "listingRef": listing_ref,
        "recipeRegistryVersion": RECIPE_REGISTRY_VERSION,
        "railRegistryVersion": RAIL_REGISTRY_VERSION,
        "parties": parties,
        "priorPhaseOutputs": prior_phase_outputs,
        "signer": {
            "kind": "fixture-substrate-signer",
            "keyRef": case["publisher"]["presentedBy"],
        },
        "startedAt": FIXTURE_NOW - 1_000,
    }


def verify_session_context(actual, case, listing_ref, prior_phase_outputs):
    expected = expected_session_context(case, listing_ref, prior_phase_outputs)
    require(isinstance(actual, dict), "session context shape")
    require(set(actual) == set(expected), "session context members")
    require(
        isinstance(actual.get("listingRef"), dict)
        and safe_integer(actual["listingRef"].get("version"), minimum=1),
        "session listing ref",
    )
    require(
        safe_integer(actual.get("recipeRegistryVersion"), minimum=1)
        and safe_integer(actual.get("railRegistryVersion"), minimum=1)
        and safe_integer(actual.get("startedAt"), minimum=1),
        "session scalar types",
    )
    for field in expected.keys() - {"parties"}:
        require(actual[field] == expected[field], f"session context {field}")
    parties = actual.get("parties")
    require(isinstance(parties, list), "session parties")
    actual_by_claim = {}
    for party in parties:
        require(isinstance(party, dict), "session party shape")
        claim = party.get("primaryClaim")
        require(claim not in actual_by_claim, "duplicate session party")
        actual_by_claim[claim] = party
    expected_by_claim = {
        party["primaryClaim"]: party for party in expected["parties"]
    }
    require(actual_by_claim == expected_by_claim, "session party roster")


def verify_sealed_input(
    case,
    listing_ref,
    negotiation,
    candidate_by_claim,
    eligible,
    composite_by_tuple,
):
    negotiate = case.get("negotiateInput")
    require(negotiate and negotiate.get("vetProvenanceInputVersion") == "1", "provenanced sealed input")
    require(not any(field in negotiate for field in ("buyerBundles", "sellerBundle", "buyerVetRefs", "sellerVetRef")), "legacy sealed fields")
    require(negotiate.get("jobId") == case["jobId"], "sealed input job")
    require(negotiate.get("listingHash") == listing_ref["contentHash"], "sealed input listing hash")
    require(
        isinstance(negotiate.get("listingRef"), dict)
        and safe_integer(negotiate["listingRef"].get("version"), minimum=1)
        and negotiate["listingRef"]
        == {"listingId": listing_ref["listingId"], "version": listing_ref["version"]},
        "sealed input listing ref",
    )
    require(canonical(negotiate.get("parameters")) == canonical(negotiation.get("parameters")), "sealed input parameters")
    verify_session_context(
        negotiate.get("sessionContext"),
        case,
        listing_ref,
        {"vet-credentials-provenanced": case["vetContextDelta"]},
    )
    require(canonical(negotiate["publisherBundle"]) == canonical(case["publisher"]), "global publisher body")
    pairs = negotiate["vetPairs"]
    require(isinstance(pairs, list) and len(pairs) == len(eligible), "vetPairs cardinality")
    pairs_by_context = {}
    for pair in pairs:
        context = pair.get("counterpartyContext")
        require(context not in pairs_by_context, "duplicate vetPair context")
        pairs_by_context[context] = pair
    require(set(pairs_by_context) == set(eligible), "vetPairs completeness")
    for context, pair in pairs_by_context.items():
        require(canonical(pair["counterpartyBundle"]) == canonical(candidate_by_claim[context]), "pair bundle")
        require(ref_key(pair["counterpartyVetRef"]) == ref_key(composite_by_tuple[(context, "counterparty")]["ref"]), "pair counterparty ref")
        require(ref_key(pair["publisherVetRef"]) == ref_key(composite_by_tuple[(context, "publisher")]["ref"]), "pair publisher ref")


def b64decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_component_signature(artifact, domain):
    signature = artifact.get("signature")
    require(isinstance(signature, dict), "missing signature")
    require(signature.get("algorithm") == "ed25519", "wrong signature algorithm")
    signer = signature.get("signer", "")
    require(signer.startswith("key:"), "fixture signer must be key claim")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer[4:]))
        payload = domain.encode("utf-8") + signing_hash(artifact, "signature").encode("ascii")
        key.verify(b64decode(signature["value"]), payload)
    except (ValueError, KeyError, InvalidSignature) as exc:
        raise InvalidChain("invalid component signature") from exc


def verify_identity(bundle, nonce=None):
    require(bundle.get("bundleVersion") == "1", "identity discriminator")
    if nonce is not None:
        require(bundle.get("sessionNonce") == nonce, "identity nonce")
    claim = bundle.get("presentedBy")
    claims = bundle.get("claims")
    require(isinstance(claims, list) and claims, "identity claims")
    require(any(item.get("ref") == claim for item in claims), "presentedBy absent")
    presentation = bundle.get("presentation", {})
    require(presentation.get("kind") == "per-claim", "presentation kind")
    signatures = presentation.get("signatures")
    require(isinstance(signatures, list) and len(signatures) == 1, "presentation signatures")
    signature = signatures[0]
    require(signature.get("ref") == claim and claim.startswith("key:"), "presentation signer")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(claim[4:]))
        payload = BUNDLE_DOMAIN.encode("utf-8") + bundle_hash(bundle).encode("ascii")
        key.verify(b64decode(signature["signature"]), payload)
    except (ValueError, KeyError, InvalidSignature) as exc:
        raise InvalidChain("invalid identity presentation") from exc


def verify_envelope(item, expected_logical, *, full_signed, gate):
    artifact = item["artifact"]
    wanted = full_hash(artifact) if full_signed else signing_hash(artifact, "signature")
    require(item["ref"]["contentHash"] == wanted, "reference content hash")
    receipt = item["receipt"]
    require(receipt["contentHash"] == wanted, "receipt content hash")
    require(receipt["logicalAddress"] == expected_logical, "receipt logical address")
    require(item["ref"]["anchor"]["locator"] == receipt["nativeAddress"], "native locator")
    require(receipt.get("observationDisposition") == "established", "receipt disposition")
    wanted_tx = hashlib.sha256(("tx:" + expected_logical + ":" + wanted).encode("utf-8")).hexdigest()
    require(receipt.get("transactionRef") == {"kind": "fixture-tx", "value": wanted_tx}, "receipt transaction")
    require(receipt.get("nonce") == "0", "receipt nonce")
    verify_receipt_proof(receipt)
    state = receipt.get("state")
    require(state in {"accepted", "included", "finalized"}, "receipt state")
    if gate == "finalized-audit-projection" and state != "finalized":
        return False
    return True


def verify_receipt_proof(receipt):
    evidence = receipt.get("evidence", {})
    kind = evidence.get("kind", "")
    require(kind.startswith("fixture-ed25519-receipt/"), "receipt proof kind")
    signer = kind.removeprefix("fixture-ed25519-receipt/")
    require(signer == RECEIPT_VALIDATOR, "receipt proof signer")
    scope = {key: value for key, value in receipt.items() if key != "evidence"}
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer[4:]))
        payload = RECEIPT_DOMAIN.encode("utf-8") + hash_value(scope).encode("ascii")
        key.verify(b64decode(evidence["value"]), payload)
    except (ValueError, KeyError, InvalidSignature) as exc:
        raise InvalidChain("invalid receipt proof") from exc


def verify_method_evidence(item, job_id, gate):
    artifact = item["artifact"]
    require(
        artifact.get("kind") in {"self-signed-assertion", "self-signed-invocation-error"},
        "method evidence kind",
    )
    identifier = artifact["identifier"]
    expected_logical = f"fixture:self-signed-evidence:{job_id}:{cf4(identifier)}"
    wanted = full_hash(artifact)
    require(item["ref"]["contentHash"] == wanted, "method evidence ref hash")
    receipt = item["receipt"]
    require(receipt["contentHash"] == wanted, "method evidence receipt hash")
    require(receipt["logicalAddress"] == expected_logical, "method evidence logical")
    require(item["ref"]["anchor"]["locator"] == receipt["nativeAddress"], "method evidence native")
    require(item["ref"]["signer"] == "key:" + identifier, "method evidence signer")
    wanted_tx = hashlib.sha256(("tx:" + expected_logical + ":" + wanted).encode("utf-8")).hexdigest()
    require(receipt["transactionRef"] == {"kind": "fixture-tx", "value": wanted_tx}, "method evidence tx")
    require(receipt["nonce"] == "0", "method evidence nonce")
    verify_receipt_proof(receipt)
    require(receipt["state"] == "finalized", "method evidence finality")
    if artifact["kind"] == "self-signed-invocation-error":
        require(artifact.get("error") == "declared assertion bytes unavailable to parser", "method invocation error")
        return "error"
    assertion = f"dacs-self-signed-claim:v1:{job_id}:key:{identifier}"
    require(artifact["assertion"] == assertion, "method assertion")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(identifier))
        key.verify(b64decode(artifact["signature"]), assertion.encode("utf-8"))
        signature_valid = True
    except (ValueError, KeyError, InvalidSignature):
        signature_valid = False
    return "pass" if signature_valid else "fail"


def roster_entries(candidates):
    unique = {}
    for candidate in candidates:
        verify_identity(candidate, candidate.get("sessionNonce"))
        claim = candidate["presentedBy"]
        entry = {"primaryClaim": claim, "bundleHash": bundle_hash(candidate)}
        if claim in unique:
            require(unique[claim] == entry and canonical(unique[claim + ":body"]) == canonical(candidate), "candidate equivocation")
        else:
            unique[claim] = entry
            unique[claim + ":body"] = candidate
    claims = sorted((key for key in unique if not key.endswith(":body")), key=lambda value: value.encode("utf-8"))
    return [unique[claim] for claim in claims]


def validate_vector(case):
    try:
        return _validate_vector(case)
    except (InvalidChain, KeyError, TypeError, IndexError, ValueError, AttributeError):
        return "fail"


def _validate_vector(case):
    gate = case["gate"]
    nonce = case["sessionNonce"]
    job_id = case["jobId"]
    listing_item = case["listing"]
    listing = listing_item["artifact"]
    verify_component_signature(listing, LISTING_DOMAIN)
    require(listing["signature"]["signer"] == listing["seller"]["identity"]["presentedBy"], "listing signer")
    verify_identity(listing["seller"]["identity"])
    require(listing.get("dacsVersion") == "1", "listing major version")
    require(safe_integer(listing.get("listingVersion"), minimum=1), "listing version")
    require(
        isinstance(listing.get("listingId"), str)
        and LISTING_ID.fullmatch(listing["listingId"]) is not None,
        "listing id",
    )
    validity = listing.get("validity", {})
    require(
        safe_integer(validity.get("notBefore"))
        and validity["notBefore"] <= FIXTURE_NOW
        and (
            validity.get("notAfter") is None
            or (
                safe_integer(validity["notAfter"])
                and validity["notAfter"] >= FIXTURE_NOW
            )
        ),
        "listing validity",
    )
    pipeline = listing.get("pipeline")
    require(
        isinstance(pipeline, list)
        and pipeline
        and all(isinstance(step, dict) for step in pipeline),
        "listing pipeline",
    )
    vet_steps = [step for step in pipeline if step.get("kind") in {"vet-credentials", "vet-credentials-provenanced"}]
    require(
        len(vet_steps) == 1
        and vet_steps[0].get("kind") == case.get("phaseKind")
        and case.get("phaseKind") in {"vet-credentials", "vet-credentials-provenanced"}
        and pipeline[0].get("kind") == case.get("phaseKind"),
        "listing Vet selection",
    )
    negotiate_steps = [step for step in pipeline if str(step.get("kind", "")).startswith("negotiate-")]
    require(len(negotiate_steps) == 1, "listing negotiation cardinality")
    negotiation = negotiate_steps[0]
    pricing = listing.get("pricing", {})
    if case.get("mode") == "ordinary":
        require(negotiation == {"kind": "negotiate-fixed-price"}, "ordinary negotiation mode")
        require(pricing.get("kind") == "fixed", "ordinary pricing mode")
        verify_positive_price(pricing.get("price"), "ordinary positive price")
        require(case.get("negotiateInput") is None, "ordinary sealed handoff")
    elif case.get("mode") == "procurement":
        require(negotiation.get("kind") == "negotiate-sealed-envelope-procurement", "procurement negotiation mode")
        parameters = negotiation.get("parameters", {})
        require(
            parameters.get("auctionMode") == "procurement"
            and safe_integer(parameters.get("commitDeadline"), minimum=1)
            and parameters["commitDeadline"] > FIXTURE_NOW
            and safe_integer(parameters.get("revealWindow"), minimum=60)
            and parameters["revealWindow"] >= 60,
            "procurement parameters",
        )
        require(
            pricing.get("kind") == "auction"
            and pricing.get("selectionRule") == parameters.get("selectionRule"),
            "procurement pricing mode",
        )
        if "reservePrice" in pricing:
            verify_positive_price(pricing["reservePrice"], "procurement reserve price")
    else:
        require(False, "unknown fixture mode")
    listing_logical = (
        f"dacs1:{cf4(listing['seller']['identity']['presentedBy'])}:"
        f"{listing['listingId']}:v{listing['listingVersion']}"
    )
    all_final = verify_envelope(listing_item, listing_logical, full_signed=False, gate=gate)
    require(listing_item["receipt"].get("state") == "finalized", "listing preverification finality")
    listing_ref = {
        "listingId": listing["listingId"],
        "version": listing["listingVersion"],
        "contentHash": signing_hash(listing, "signature"),
    }

    verify_identity(case["publisher"], nonce)
    require(
        case["publisher"]["presentedBy"]
        == listing["seller"]["identity"]["presentedBy"],
        "listing/session publisher identity",
    )
    entries = roster_entries(case["candidates"])
    require(entries, "empty roster")
    roster_hash = hash_value(entries)
    candidate_by_claim = {candidate["presentedBy"]: candidate for candidate in case["candidates"]}
    require(len(candidate_by_claim) == len(entries), "duplicate candidate body not normalized")

    # Resolve these only after the complete authorization/input barrier below;
    # the ordering models PVPC-2's no-verification-side-effect gate.
    result_items = case["verificationResults"]
    method_evidence_by_ref = {
        ref_key(item["ref"]): item for item in case.get("methodEvidence", [])
    }
    result_by_ref = {}

    phase_kind = case["phaseKind"]
    if phase_kind == "vet-credentials":
        require(not case["authorizations"], "legacy phase carries authorization")
        require(all("recordVersion" in item["artifact"] and "provenancedRecordVersion" not in item["artifact"] for item in case["composites"]), "legacy type")
        return "pass" if all_final else "indeterminate"
    require(phase_kind == "vet-credentials-provenanced", "unknown phase")

    auth_by_ref = {}
    auth_by_tuple = {}
    shared_pin = case["recipeRegistryVersion"]
    require(
        safe_integer(shared_pin, minimum=1)
        and shared_pin == RECIPE_REGISTRY_VERSION,
        "recipe registry version",
    )
    for item in case["authorizations"]:
        artifact = item["artifact"]
        require(artifact.get("vetAuthorizationVersion") == "1", "authorization discriminator")
        require("recordVersion" not in artifact and "provenancedRecordVersion" not in artifact, "authorization coercion")
        verify_component_signature(artifact, AUTH_DOMAIN)
        all_final &= verify_envelope(item, auth_logical(artifact), full_signed=False, gate=gate)
        authorization_listing_ref = artifact.get("listingRef", {})
        require(
            artifact["jobId"] == job_id
            and isinstance(authorization_listing_ref, dict)
            and safe_integer(authorization_listing_ref.get("version"), minimum=1)
            and authorization_listing_ref == listing_ref,
            "authorization session/listing",
        )
        require(artifact["recipeRegistryVersion"] == shared_pin, "recipe registry pin")
        require(
            safe_integer(artifact.get("counterpartyCount"), minimum=1)
            and artifact["counterpartyCount"] == len(entries),
            "roster count",
        )
        require(artifact["counterpartySetHash"] == roster_hash, "roster hash")
        require(safe_integer(artifact.get("authorizedAt"), minimum=1), "authorization time")
        role = artifact["evaluatedRole"]
        require(role in ROLE_ORDER, "evaluated role")
        require(artifact["authorizerRole"] != role, "opposite role")
        verify_identity(artifact["evaluatedIdentity"], nonce)
        verify_identity(artifact["authorizerIdentity"], nonce)
        verify_identity(artifact["verifierIdentity"], nonce)
        require(artifact["evaluatedParty"] == artifact["evaluatedIdentity"]["presentedBy"], "evaluated party")
        require(artifact["evaluatedBundleHash"] == bundle_hash(artifact["evaluatedIdentity"]), "evaluated hash")
        require(artifact["requirementHash"] == hash_value(artifact["requirement"]), "requirement hash")
        require(artifact["signature"]["signer"] == artifact["authorizerIdentity"]["presentedBy"], "authorizer signer")
        context = artifact["counterpartyContext"]
        require(context in candidate_by_claim, "unknown context")
        require(context != case["publisher"]["presentedBy"], "commerce parties share primary claim")
        if role == "counterparty":
            require(artifact["authorizerRole"] == "publisher", "counterparty authorizer role")
            require(canonical(artifact["evaluatedIdentity"]) == canonical(candidate_by_claim[context]), "counterparty body")
            require(canonical(artifact["authorizerIdentity"]) == canonical(case["publisher"]), "publisher authorizer body")
            require(context == artifact["evaluatedIdentity"]["presentedBy"], "counterparty context")
            require(artifact["requirementOrigin"] == {"kind": "listing", "field": "buyerRequirement"}, "listing origin")
            require(canonical(artifact["requirement"]) == canonical(listing["buyerRequirement"]), "listing requirement")
        else:
            require(artifact["authorizerRole"] == "counterparty", "publisher authorizer role")
            require(canonical(artifact["evaluatedIdentity"]) == canonical(case["publisher"]), "publisher evaluated body")
            require(canonical(artifact["authorizerIdentity"]) == canonical(candidate_by_claim[context]), "candidate authorizer body")
            require(context == artifact["authorizerIdentity"]["presentedBy"], "publisher context")
            require(artifact["requirementOrigin"] == {"kind": "party-declared"}, "party requirement origin")
        key = (context, role)
        require(key not in auth_by_tuple, "duplicate authorization tuple")
        auth_by_tuple[key] = item
        require(ref_key(item["ref"]) not in auth_by_ref, "duplicate authorization ref")
        auth_by_ref[ref_key(item["ref"])] = item

    if case.get("preauthorizationBarrier") == "not-reached":
        require(len(auth_by_tuple) < 2 * len(entries), "partial authorization cardinality")
        projection = case.get("preauthorizationProjection", {})
        require(
            projection.get("projectionKind") == "vet-preauthorization-collection",
            "preauthorization projection kind",
        )
        require(
            projection.get("authorizationRefs")
            == [item["ref"] for item in case["authorizations"]],
            "collected authorization refs",
        )
        require(not case["composites"], "pre-barrier Composite side effect")
        require(not result_items, "pre-barrier VerifyResult side effect")
        require(not case.get("methodEvidence", []), "pre-barrier method side effect")
        require(
            case.get("phaseInput") is None and case.get("vetContextDelta") is None,
            "pre-barrier wire input/output",
        )
        require(
            all(
                projection.get(field) == 0
                for field in (
                    "claimLookupCount",
                    "invocationCount",
                    "verifyResultCount",
                    "methodEvidenceCount",
                    "compositeCount",
                )
            ),
            "pre-barrier side-effect counts",
        )
        require(case.get("agreementProjection") is None and case.get("negotiateInput") is None, "pre-barrier downstream projection")
        audit = case.get("auditProjection", {})
        require(audit.get("projectionKind") == "vet-provenance-audit-projection", "audit projection kind")
        require("phaseSummary" not in audit, "pre-barrier phase was not invoked")
        require(
            audit.get("phaseDisposition")
            == {
                "index": 0,
                "kind": "vet-credentials-provenanced",
                "state": "not-invoked",
                "cause": "party-withdrawal",
            },
            "pre-barrier phase disposition",
        )
        require(
            audit.get("outcome") == "aborted-by-self"
            and audit.get("abortEvent")
            == "fixture-party-withdrawal-before-invocation",
            "pre-barrier abort projection",
        )
        require(audit.get("faultedParty") is None, "pre-barrier fault attribution")
        require(audit.get("winnerMappingPresent") is False, "pre-barrier winner mapping")
        require(audit.get("representationDisposition") == "projected-prebarrier-nonattributable", "pre-barrier representation")
        require(audit.get("reputationDisposition") == "exclude", "pre-barrier reputation")
        require(audit.get("vetRecords") == expected_vet_refs(case), "pre-barrier vetRecords")
        return "pass" if all_final else "indeterminate"

    require("preauthorizationBarrier" not in case, "unexpected barrier marker")
    require("preauthorizationProjection" not in case, "unexpected preauthorization projection")
    phase_input = case.get("phaseInput", {})
    require(phase_input.get("jobId") == job_id, "phase input job")
    require(phase_input.get("recipeRegistryVersion") == shared_pin, "phase input registry pin")
    require(
        safe_integer(phase_input.get("attempt"), minimum=1)
        and phase_input["attempt"] == 1,
        "phase input attempt",
    )
    verify_session_context(
        phase_input.get("sessionContext"), case, listing_ref, {}
    )
    require(not any(field in phase_input for field in ("requirement", "actor", "verifierIdentity")), "phase input override")
    invocations = phase_input.get("invocations")
    require(len(auth_by_tuple) == 2 * len(entries), "authorization cardinality")
    for entry in entries:
        context = entry["primaryClaim"]
        require((context, "counterparty") in auth_by_tuple and (context, "publisher") in auth_by_tuple, "pair closure")
        cp = auth_by_tuple[(context, "counterparty")]["artifact"]
        pub = auth_by_tuple[(context, "publisher")]["artifact"]
        require(canonical(cp["evaluatedIdentity"]) == canonical(pub["authorizerIdentity"]), "candidate cross-body")
        require(canonical(pub["evaluatedIdentity"]) == canonical(cp["authorizerIdentity"]), "publisher cross-body")

    require(isinstance(invocations, list) and len(invocations) == 2 * len(entries), "phase invocation cardinality")
    expected_invocation_keys = {
        (context, role)
        for context in sorted(candidate_by_claim, key=lambda value: value.encode("utf-8"))
        for role in ("counterparty", "publisher")
    }
    invocation_keys = [
        (item.get("counterpartyContext"), item.get("evaluatedRole"))
        for item in invocations
    ]
    require(
        len(set(invocation_keys)) == len(invocation_keys)
        and set(invocation_keys) == expected_invocation_keys,
        "phase invocation keyed set",
    )
    for invocation in invocations:
        require(not any(field in invocation for field in ("requirement", "actor", "verifierIdentity")), "invocation override")
        key = (invocation["counterpartyContext"], invocation["evaluatedRole"])
        auth_item = auth_by_tuple[key]
        require(ref_key(invocation["authorizationRef"]) == ref_key(auth_item["ref"]), "invocation authorization")
        require(canonical(invocation["bundleToVet"]) == canonical(auth_item["artifact"]["evaluatedIdentity"]), "invocation body")

    # Only after the full preauthorization barrier do method evidence and
    # VerifyResults become eligible for resolution/replay.
    for item in result_items:
        artifact = item["artifact"]
        verify_component_signature(artifact, VERIFY_DOMAIN)
        expected = (
            f"dacs2:{job_id}:{artifact['scheme']}:"
            f"{cf4(artifact['identifier'])}:v{artifact['recipeVersion']}"
        )
        all_final &= verify_envelope(item, expected, full_signed=False, gate=gate)
        evidence_item = method_evidence_by_ref.get(ref_key(artifact["attestation"]))
        require(evidence_item is not None, "method evidence resolution")
        derived_decision = verify_method_evidence(evidence_item, job_id, gate)
        require(artifact["decision"] == derived_decision, "method-native decision")
        require(artifact["attestation"].get("signer") == "key:" + artifact["identifier"], "method evidence subject")
        require(safe_integer(artifact.get("recipeVersion"), minimum=1), "VerifyResult recipe version")
        ref = {
            "anchor": item["ref"]["anchor"],
            "contentHash": item["ref"]["contentHash"],
            "recipeVersion": artifact["recipeVersion"],
        }
        require(result_ref_key(ref) not in result_by_ref, "duplicate VerifyResult ref")
        result_by_ref[result_ref_key(ref)] = artifact

    retry_projection = case.get("vetRetryProjection")
    if retry_projection is not None:
        require(
            set(retry_projection)
            == {
                "projectionKind",
                "counterpartyContext",
                "evaluatedRole",
                "decision",
                "retryState",
                "attempt",
                "emittedCompositeCount",
                "phaseOutputEmitted",
                "admissionEmitted",
                "agreementEmitted",
                "bundleEmitted",
                "pinnedRetryPolicyProjection",
            },
            "retry projection members",
        )
        require(
            retry_projection.get("projectionKind") == "vet-retry-pending"
            and retry_projection.get("evaluatedRole") == "counterparty"
            and retry_projection.get("decision") == "error"
            and retry_projection.get("retryState") == "pending",
            "retry projection state",
        )
        require(
            retry_projection.get("attempt") == phase_input["attempt"]
            and retry_projection.get("emittedCompositeCount") == 0
            and retry_projection.get("phaseOutputEmitted") is False
            and retry_projection.get("admissionEmitted") is False
            and retry_projection.get("agreementEmitted") is False
            and retry_projection.get("bundleEmitted") is False,
            "retry projection zero effects",
        )
        require(not case["composites"], "pending retry Composite emission")
        require(case.get("vetContextDelta") is None, "pending retry phase output")
        require(
            case.get("negotiateInput") is None
            and case.get("agreementProjection") is None,
            "pending retry downstream admission",
        )

        pending_context = retry_projection.get("counterpartyContext")
        candidate = candidate_by_claim.get(pending_context)
        require(candidate is not None, "pending retry candidate context")
        candidate_key_claims = [
            claim
            for claim in candidate.get("claims", [])
            if claim.get("ref", "").startswith("key:")
        ]
        require(
            len(candidate_key_claims) == 1
            and isinstance(candidate_key_claims[0].get("verifiedBy"), dict),
            "pending retry candidate result binding",
        )
        pending_result = result_by_ref.get(
            result_ref_key(candidate_key_claims[0]["verifiedBy"])
        )
        error_results = [
            result for result in result_by_ref.values() if result.get("decision") == "error"
        ]
        require(
            pending_result is not None
            and len(error_results) == 1
            and pending_result is error_results[0]
            and pending_result.get("scheme") == "key"
            and "key:" + pending_result.get("identifier", "") == pending_context,
            "pending retry authenticated error result",
        )

        policy_projection = retry_projection.get("pinnedRetryPolicyProjection")
        require(
            isinstance(policy_projection, dict)
            and set(policy_projection)
            == {
                "projectionKind",
                "recipeRegistryVersion",
                "scheme",
                "recipeVersion",
                "policy",
                "policyHash",
            },
            "pinned retry policy projection members",
        )
        require(
            policy_projection.get("projectionKind")
            == "pinned-recipe-retry-policy"
            and policy_projection.get("recipeRegistryVersion") == shared_pin
            and policy_projection.get("scheme") == pending_result["scheme"]
            and policy_projection.get("recipeVersion")
            == pending_result["recipeVersion"],
            "pinned retry recipe lookup key",
        )
        fixture_policy = {
            "retryClass": "transient",
            "retryBudget": 2,
            "retryOnIndeterminate": False,
        }
        policy = policy_projection.get("policy")
        require(policy == fixture_policy, "pinned retry policy")
        require(
            policy_projection.get("policyHash") == hash_value(policy),
            "pinned retry policy hash",
        )
        require(
            policy.get("retryClass") == "transient"
            and safe_integer(policy.get("retryBudget"), minimum=1)
            and phase_input["attempt"] < policy["retryBudget"]
            and policy.get("retryOnIndeterminate") is False,
            "retry remains available under pinned policy",
        )

        audit = case.get("auditProjection", {})
        require(
            audit.get("projectionKind") == "vet-provenance-audit-projection"
            and "outcome" not in audit
            and "phaseSummary" not in audit
            and audit.get("sessionState") == "vet-pending",
            "pending retry nonterminal audit projection",
        )
        require(
            audit.get("phaseDisposition")
            == {
                "index": 0,
                "kind": "vet-credentials-provenanced",
                "decision": "error",
                "retryState": "pending",
            },
            "pending retry phase disposition",
        )
        require(audit.get("winnerMappingPresent") is False, "pending retry winner mapping")
        require(audit.get("faultedParty") is None, "pending retry fault attribution")
        require(
            audit.get("representationDisposition")
            == "exclude-retryable-or-indeterminate",
            "pending retry representation exclusion",
        )
        require(
            audit.get("reputationDisposition") == "exclude",
            "pending retry reputation exclusion",
        )
        require(
            audit.get("vetRecords") == expected_vet_refs(case),
            "pending retry authorization-only vetRecords",
        )
        return "indeterminate"

    composite_by_tuple = {}
    composite_by_ref = {}
    decisions = {}
    for item in case["composites"]:
        artifact = item["artifact"]
        require(artifact.get("provenancedRecordVersion") == "1", "composite discriminator")
        require("recordVersion" not in artifact and "vetAuthorizationVersion" not in artifact, "composite coercion")
        verify_component_signature(artifact, COMPOSITE_DOMAIN)
        all_final &= verify_envelope(item, composite_logical(artifact), full_signed=False, gate=gate)
        auth_item = auth_by_ref.get(ref_key(artifact["authorizationRef"]))
        require(auth_item is not None, "authorization ref resolution")
        authorization = auth_item["artifact"]
        for record_field, auth_field in (
            ("jobId", "jobId"),
            ("evaluatedRole", "evaluatedRole"),
            ("counterpartyContext", "counterpartyContext"),
            ("evaluatedParty", "evaluatedParty"),
            ("bundleHash", "evaluatedBundleHash"),
            ("requirementHash", "requirementHash"),
        ):
            require(artifact[record_field] == authorization[auth_field], "composite authorization tuple")
        require(artifact["signature"]["signer"] == authorization["verifierIdentity"]["presentedBy"], "authorized verifier")

        required = authorization["requirement"].get("required", [])
        require(len(required) == 1 and required[0]["scheme"] == "key" and required[0]["verificationRequired"] is True, "fixture requirement")
        claims = authorization["evaluatedIdentity"].get("claims", [])
        matches = [claim for claim in claims if claim.get("ref", "").startswith("key:")]
        require(len(matches) == 1 and "verifiedBy" in matches[0], "required claim")
        require(len(artifact["freshness"]) == 1, "freshness cardinality")
        evidence_ref = artifact["freshness"][0]
        require(result_ref_key(evidence_ref) == result_ref_key(matches[0]["verifiedBy"]), "result replay/body binding")
        result = result_by_ref.get(result_ref_key(evidence_ref))
        require(result is not None, "result resolution")
        require(result["scheme"] == "key" and "key:" + result["identifier"] == matches[0]["ref"], "result identifier")
        require(
            safe_integer(evidence_ref.get("recipeVersion"), minimum=1)
            and result["recipeVersion"] == evidence_ref["recipeVersion"],
            "result recipe",
        )
        require(artifact["overallDecision"] == result["decision"], "decision recomputation")
        key = (artifact["counterpartyContext"], artifact["evaluatedRole"])
        require(key not in composite_by_tuple, "duplicate composite tuple")
        composite_by_tuple[key] = item
        composite_by_ref[ref_key(item["ref"])] = item
        decisions[key] = result["decision"]

    require(len(composite_by_tuple) == 2 * len(entries), "composite cardinality")

    expected_records = []
    for context in sorted(candidate_by_claim, key=lambda value: value.encode("utf-8")):
        for role in ("counterparty", "publisher"):
            composite = composite_by_tuple[(context, role)]
            auth = auth_by_tuple[(context, role)]
            expected_records.append(
                {
                    "counterpartyContext": context,
                    "evaluatedRole": role,
                    "compositeRecord": composite["ref"],
                    "authorizationRecord": auth["ref"],
                    "overallDecision": composite["artifact"]["overallDecision"],
                }
            )
    require(case["vetContextDelta"]["records"] == expected_records, "phase record ordering/binding")
    require(case["auditProjection"]["vetRecords"] == expected_vet_refs(case), "vetRecords canonical order")

    ambiguous = any(decision in {"error", "indeterminate"} for decision in decisions.values())
    eligible = []
    for context in sorted(candidate_by_claim, key=lambda value: value.encode("utf-8")):
        pair = {decisions[(context, "counterparty")], decisions[(context, "publisher")]}
        if pair == {"pass"}:
            eligible.append(context)
    if ambiguous:
        require(case["vetContextDelta"]["eligibleCounterparties"] == [], "ambiguous phase admission")
    else:
        require(case["vetContextDelta"]["eligibleCounterparties"] == eligible, "eligible set")
    if case["mode"] == "procurement" and case.get("negotiateInput") is not None:
        verify_sealed_input(
            case,
            listing_ref,
            negotiation,
            candidate_by_claim,
            eligible,
            composite_by_tuple,
        )

    audit = case["auditProjection"]
    require(audit.get("projectionKind") == "vet-provenance-audit-projection", "audit projection kind")
    if ambiguous:
        require("outcome" not in audit and "phaseSummary" not in audit, "ambiguous nonterminal projection")
        require(audit.get("sessionState") == "vet-pending", "ambiguous session state")
        require(
            audit.get("phaseDisposition")
            == {
                "index": 0,
                "kind": "vet-credentials-provenanced",
                "decision": "error",
                "retryState": "pending",
            },
            "ambiguous phase disposition",
        )
        require(case.get("agreementProjection") is None and case.get("negotiateInput") is None, "ambiguous downstream admission")
        require(audit.get("winnerMappingPresent") is False, "ambiguous winner mapping")
        require(audit.get("faultedParty") is None, "ambiguous fault attribution")
        require(audit.get("representationDisposition") == "exclude-retryable-or-indeterminate", "ambiguous representation exclusion")
        require(audit.get("reputationDisposition") == "exclude", "ambiguous reputation exclusion")
        return "indeterminate"

    pending_finality = not all_final
    if pending_finality:
        require("outcome" not in audit and "phaseSummary" not in audit, "pending-finality nonterminal projection")
        require(audit.get("sessionState") == "audit-pending", "pending-finality session state")
        require(
            audit.get("phaseDisposition")
            == {"index": 0, "kind": "vet-credentials-provenanced", "outcome": "ok"},
            "pending-finality phase disposition",
        )
        require(audit.get("faultedParty") is None, "pending-finality fault attribution")
        require(audit.get("representationDisposition") == "exclude-pending-finality", "pending-finality representation exclusion")
        require(audit.get("reputationDisposition") == "exclude", "pending-finality reputation exclusion")
    else:
        require(
            audit.get("phaseSummary", {}).get("index") == 0
            and audit.get("phaseSummary", {}).get("kind") == phase_kind,
            "audit phase index/kind",
        )
    if len(entries) > 1 and not audit.get("winnerMappingPresent"):
        require(audit.get("representationDisposition") == "exclude-prewinner-multicandidate", "prewinner representation exclusion")
        require(audit.get("reputationDisposition") == "exclude", "prewinner reputation exclusion")
        require(audit.get("faultedParty") is None, "prewinner fault attribution")
        require(
            audit.get("phaseSummary")
            == {
                "index": 0,
                "kind": "vet-credentials-provenanced",
                "outcome": "fail",
                "errorClass": "counterparty",
            },
            "prewinner phase summary",
        )
        require(case.get("agreementProjection") is None, "prewinner agreement projection")
        return "indeterminate"

    if pending_finality or audit.get("outcome") == "completed":
        if not pending_finality:
            require(audit.get("representationDisposition") == "projected-representable", "representable projection")
            require(audit.get("reputationDisposition") == "include", "representable reputation projection")
            require(audit["phaseSummary"].get("outcome") == "ok" and audit["phaseSummary"].get("errorClass") is None, "completed phase summary")
        require(eligible, "completed without eligible pair")
        agreement = case.get("agreementProjection")
        require(agreement is not None and audit.get("winnerMappingPresent"), "completed agreement projection")
        if case["mode"] == "ordinary":
            require(len(entries) == 1 and len(agreement["parties"]) == 2, "bilateral agreement")
            context = eligible[0]
            expected = {
                case["publisher"]["presentedBy"]: ref_key(composite_by_tuple[(context, "publisher")]["ref"]),
                context: ref_key(composite_by_tuple[(context, "counterparty")]["ref"]),
            }
            require({party["primaryClaim"] for party in agreement["parties"]} == set(expected), "bilateral parties")
            for party in agreement["parties"]:
                require(ref_key(party["vetRecordRef"]) == expected[party["primaryClaim"]], "bilateral vet ref")
                expected_bundle = case["publisher"] if party["primaryClaim"] == case["publisher"]["presentedBy"] else candidate_by_claim[party["primaryClaim"]]
                require(party.get("bundleHash") == bundle_hash(expected_bundle), "bilateral party bundle hash")
                wanted_role = "seller" if party["primaryClaim"] == case["publisher"]["presentedBy"] else "buyer"
                require(party.get("role") == wanted_role, "bilateral agreement role")
        else:
            agreement_claims = {party["primaryClaim"] for party in agreement["parties"] if party["primaryClaim"] != case["publisher"]["presentedBy"]}
            require(agreement_claims == set(eligible), "agreement eligible completeness")
            winner = agreement["winnerContext"]
            require(winner in eligible, "winner eligibility")
            publisher_parties = [party for party in agreement["parties"] if party["primaryClaim"] == case["publisher"]["presentedBy"]]
            require(len(publisher_parties) == 1, "publisher agreement party")
            require(publisher_parties[0].get("role") == "buyer", "procurement publisher role")
            require(ref_key(publisher_parties[0]["vetRecordRef"]) == ref_key(composite_by_tuple[(winner, "publisher")]["ref"]), "winner publisher ref")
            for party in agreement["parties"]:
                expected_bundle = case["publisher"] if party["primaryClaim"] == case["publisher"]["presentedBy"] else candidate_by_claim[party["primaryClaim"]]
                require(party.get("bundleHash") == bundle_hash(expected_bundle), "procurement party bundle hash")
                if party["primaryClaim"] != case["publisher"]["presentedBy"]:
                    require(ref_key(party["vetRecordRef"]) == ref_key(composite_by_tuple[(party["primaryClaim"], "counterparty")]["ref"]), "candidate agreement ref")
                    wanted_role = "seller" if party["primaryClaim"] == winner else "bidder-non-winning"
                    require(party.get("role") == wanted_role, "procurement candidate role")
    else:
        require(len(entries) == 1, "preagreement multi-candidate terminal")
        require(audit.get("outcome") == "failed-counterparty", "bilateral failure outcome")
        require(audit.get("phaseSummary", {}).get("outcome") == "fail", "bilateral phase failure")
        require(case.get("agreementProjection") is None and case.get("negotiateInput") is None, "failed Vet downstream admission")
        require(case["vetContextDelta"]["eligibleCounterparties"] == [], "failed Vet eligibility")
        failing_roles = {role for (context, role), decision in decisions.items() if decision == "fail"}
        if len(failing_roles) != 1:
            require(audit.get("representationDisposition") == "exclude-current-single-fault-type", "multi-fault representation exclusion")
            require(audit.get("reputationDisposition") == "exclude", "multi-fault reputation exclusion")
            require(audit.get("faultedParty") is None, "multi-fault attribution")
            require(
                audit.get("phaseSummary")
                == {
                    "index": 0,
                    "kind": "vet-credentials-provenanced",
                    "outcome": "fail",
                    "errorClass": "counterparty",
                },
                "multi-fault phase summary",
            )
            return "indeterminate"
        require(audit.get("representationDisposition") == "projected-representable", "representable projection")
        require(audit.get("reputationDisposition") == "include", "representable reputation projection")
        expected_fault = "seller" if "publisher" in failing_roles else "buyer"
        require(audit.get("faultedParty") == expected_fault, "faultedParty mapping")
        require(audit["phaseSummary"].get("errorClass") == "counterparty", "errorClass mapping")

    return "pass" if all_final else "indeterminate"


class VetProvenanceVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        cls.compact_vectors = cls.data["vectors"]
        cls.vectors = expand_compact_vectors(cls.compact_vectors)

    def test_metadata_and_set_hash(self):
        self.assertEqual(self.data["set"], VECTOR_PATH.stem)
        self.assertEqual(self.data["count"], len(self.compact_vectors))
        self.assertEqual(len(self.compact_vectors), len(self.vectors))
        names = [vector["name"] for vector in self.compact_vectors]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(self.data["hash"], collection_hash(self.compact_vectors))
        self.assertEqual(self.data["expandedHash"], collection_hash(self.vectors))
        self.assertGreaterEqual(len(names), 30)

    def test_compact_representation_contract(self):
        self.assertEqual(
            self.data["representation"],
            {
                "kind": "two-literal-bases-with-rfc6902-subset-patches",
                "baseVectors": list(BASE_VECTOR_NAMES),
                "baseDepth": 1,
                "patchOperations": ["add", "remove", "replace"],
                "hashScope": "represented compact vectors array",
                "expandedHashScope": "semantic vectors array with every patch expanded to its full input and representation-only members removed",
                "expandedInputHashScope": "RFC 8785 JCS hash of each vector's fully expanded input",
            },
        )
        literal = [
            vector["name"] for vector in self.compact_vectors if "input" in vector
        ]
        self.assertEqual(literal, list(BASE_VECTOR_NAMES))
        for vector in self.compact_vectors:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    vector["expandedInputHash"],
                    hash_value(
                        next(
                            expanded["input"]
                            for expanded in self.vectors
                            if expanded["name"] == vector["name"]
                        )
                    ),
                )
                if vector["name"] in BASE_VECTOR_NAMES:
                    self.assertNotIn("base", vector)
                    self.assertNotIn("patch", vector)
                else:
                    self.assertNotIn("input", vector)
                    self.assertIn(vector["base"], BASE_VECTOR_NAMES)
                    self.assertIsInstance(vector["patch"], list)

    def test_strict_patch_expander_rejects_ambiguous_or_invalid_patches(self):
        rejected = {
            "unsupported-op": [{"op": "copy", "path": "/a", "from": "/b"}],
            "unexpected-member": [
                {"op": "remove", "path": "/a", "value": None}
            ],
            "malformed-pointer": [
                {"op": "replace", "path": "/bad~2token", "value": 2}
            ],
            "duplicate-path": [
                {"op": "replace", "path": "/a", "value": 2},
                {"op": "replace", "path": "/a", "value": 3},
            ],
            "overlapping-path": [
                {"op": "replace", "path": "/a", "value": {}},
                {"op": "add", "path": "/a/b", "value": 3},
            ],
            "missing-target": [
                {"op": "replace", "path": "/missing", "value": 2}
            ],
            "array-out-of-bounds": [
                {"op": "replace", "path": "/items/2", "value": 2}
            ],
        }
        base = {"a": 1, "items": [0]}
        for label, patch in rejected.items():
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    strict_apply_patch(base, patch)

        escaped = strict_apply_patch(
            {"a/b": {"~key": 1}},
            [{"op": "replace", "path": "/a~1b/~0key", "value": 2}],
        )
        self.assertEqual(escaped, {"a/b": {"~key": 2}})

        recursive = copy.deepcopy(self.compact_vectors)
        recursive[0]["base"] = BASE_VECTOR_NAMES[1]
        recursive[0]["patch"] = []
        with self.assertRaises(ValueError):
            expand_compact_vectors(recursive)

        malformed_base = copy.deepcopy(self.compact_vectors)
        next(
            vector for vector in malformed_base if "patch" in vector
        )["base"] = []
        with self.assertRaises(ValueError):
            expand_compact_vectors(malformed_base)

    def test_domains_match_registered_values(self):
        self.assertEqual(self.data["domains"]["authorization"], AUTH_DOMAIN)
        self.assertEqual(self.data["domains"]["provenancedComposite"], COMPOSITE_DOMAIN)
        self.assertEqual(self.data["domains"]["legacyComposite"], LEGACY_COMPOSITE_DOMAIN)
        core = (ROOT / "spec" / "CORE.md").read_text(encoding="utf-8")
        self.assertIn(AUTH_DOMAIN, core)
        self.assertIn(COMPOSITE_DOMAIN, core)

    def test_new_artifact_hashes_follow_core_template(self):
        intentional = {
            "authorization-full-signed-hash-is-not-content-hash",
            "composite-full-signed-hash-is-not-content-hash",
        }
        for vector in self.vectors:
            for collection in ("authorizations", "composites"):
                for item in vector["input"][collection]:
                    artifact = item["artifact"]
                    if collection == "composites" and "provenancedRecordVersion" not in artifact:
                        continue
                    if vector["name"] not in intentional:
                        self.assertEqual(item["ref"]["contentHash"], signing_hash(artifact, "signature"))
                        self.assertEqual(item["receipt"]["contentHash"], signing_hash(artifact, "signature"))

    def test_independent_oracle_matches_every_expected_verdict(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(validate_vector(vector["input"]), vector["expected"])

    def test_generator_is_deterministic(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate_vet_provenance_vectors.py"), "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
