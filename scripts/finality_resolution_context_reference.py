#!/usr/bin/env python3
"""Fixture-only verifier for finality resolution context version 1.

The verifier deliberately supports one synthetic binding and one fixed
all-authorities policy.  Production network/provider mappings are not inferred.
The historical single-view verifier is injected by its caller so this module can
enforce the new acquisition boundary without changing legacy canonical bytes.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import math
from dataclasses import dataclass, is_dataclass
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from scripts.jcs import canonicalize
except ImportError:
    from jcs import canonicalize


CONTEXT_VERSION = "1"
RESPONSE_VERSION = "1"
CAPABILITY = "finality-resolution-context-v1"
RESPONSE_DOMAIN = "dacs-finality-observation-response:v1:"
FIXTURE_BINDING = "dacs-finality-synthetic-fixture-v1"
FIXTURE_POLICY_ID = "dacs-finality-all-authorities-fixture"
FIXTURE_POLICY_VERSION = "1"
SHA256_HEX = frozenset("0123456789abcdef")
DECISION_ORDER = {"pass": 0, "indeterminate": 1, "fail": 2, "error": 3}


def canonical_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")


def hash_value(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def artifact_hash(value: dict, omitted: str) -> str:
    return hash_value({key: item for key, item in value.items() if key != omitted})


def response_hash(response: dict) -> str:
    return hash_value(response)


def response_signature_hash(response: dict) -> str:
    return artifact_hash(response, "signature")


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in SHA256_HEX for character in value)
    )


def _finite_time(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0 <= value <= 9_007_199_254_740_991
    )


def _minimal_uint(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value.isascii()
        and value.isdigit()
        and (value == "0" or not value.startswith("0"))
    )


def _exact(value: Any, required: set[str], optional: set[str] = frozenset()) -> bool:
    return isinstance(value, dict) and required <= set(value) <= required | optional


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _b64url(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("non-canonical Base64URL")
    if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in value):
        raise ValueError("non-canonical Base64URL")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("non-minimal Base64URL")
    return raw


@dataclass(frozen=True)
class FinalityResolutionAuthority:
    """Verifier-owned authority retained after issuing one exact query."""

    authenticated: bool
    policy: dict
    issued_query: dict
    checkpoint_source: dict
    policy_source: dict
    authority_set_source: dict
    base_trusted: dict
    verification_time_ms: int | float
    acquisition_records: tuple[dict, ...] = ()
    retained_responses: tuple[dict, ...] = ()
    mode: str = "current"
    replay_value: dict | None = None


def fixture_policy(authorities: list[dict]) -> dict:
    """Build the only registered reference policy; caller order is policy order."""
    return {
        "policyId": FIXTURE_POLICY_ID,
        "policyVersion": FIXTURE_POLICY_VERSION,
        "bindingCodec": FIXTURE_BINDING,
        "bindingCodecVersion": "1",
        "fixtureOnly": True,
        "authorityEpoch": "fixture-epoch-392-d2",
        "authorities": copy.deepcopy(authorities),
        "unavailableReasons": ["maintenance", "not-observed"],
        "maxObservationAgeMs": 60_000,
        "acquisitionClock": "unix-ms",
    }


def _policy_shape(policy: Any) -> bool:
    required = {
        "policyId", "policyVersion", "bindingCodec", "bindingCodecVersion",
        "fixtureOnly", "authorityEpoch", "authorities", "unavailableReasons",
        "maxObservationAgeMs", "acquisitionClock",
    }
    if not _exact(policy, required):
        return False
    if (
        policy.get("policyId") != FIXTURE_POLICY_ID
        or policy.get("policyVersion") != FIXTURE_POLICY_VERSION
        or policy.get("bindingCodec") != FIXTURE_BINDING
        or policy.get("bindingCodecVersion") != "1"
        or policy.get("fixtureOnly") is not True
        or policy.get("authorityEpoch") != "fixture-epoch-392-d2"
        or policy.get("acquisitionClock") != "unix-ms"
        or not _finite_time(policy.get("maxObservationAgeMs"))
        or policy["maxObservationAgeMs"] <= 0
        or not isinstance(policy.get("unavailableReasons"), list)
        or not policy["unavailableReasons"]
        or any(not _nonempty(reason) for reason in policy["unavailableReasons"])
        or len(policy["unavailableReasons"]) != len(set(policy["unavailableReasons"]))
        or not isinstance(policy.get("authorities"), list)
        or not policy["authorities"]
    ):
        return False
    authority_ids = []
    for seat in policy["authorities"]:
        if not _exact(seat, {"authorityId", "verificationKeys"}):
            return False
        keys = seat.get("verificationKeys")
        if (
            not _nonempty(seat.get("authorityId"))
            or not isinstance(keys, list)
            or not keys
        ):
            return False
        key_ids = []
        for key in keys:
            if not _exact(key, {"keyId", "algorithm", "publicKey"}):
                return False
            try:
                raw = _b64url(key.get("publicKey"))
            except (ValueError, TypeError, binascii.Error):
                return False
            if (
                not _nonempty(key.get("keyId"))
                or key.get("algorithm") != "ed25519"
                or len(raw) != 32
            ):
                return False
            key_ids.append(key["keyId"])
        if len(key_ids) != len(set(key_ids)):
            return False
        authority_ids.append(seat["authorityId"])
    return len(authority_ids) == len(set(authority_ids))


def _source_ref(value: Any) -> bool:
    return (
        _exact(value, {"kind", "contentHash"})
        and value.get("kind") == "authenticated-fixture"
        and _sha256(value.get("contentHash"))
    )


def derive_query(
    value: dict,
    base_trusted: dict,
    policy: dict,
    checkpoint: dict,
    *,
    nonce: str,
    issued_at: int | float,
    expires_at: int | float,
    evaluation_purpose: str = "settlement-finality",
    composite_leg_id: str | None = None,
    composite_relationship_hash: str | None = None,
) -> dict:
    """Derive the complete query from verifier-owned inputs before acquisition."""
    evidence = value["evidence"]
    agreement = value["agreement"]
    rail = value["rail"]
    profile = rail["consumerFinalityProfile"]
    if profile.get("finalityResolutionCapability") != CAPABILITY:
        raise ValueError("signed rail profile does not select resolution context v1")
    session = base_trusted["sessionAuthorityByJob"][evidence["jobId"]]
    settlement = profile["settlement"]
    expected_checkpoint_id = (
        "fixture-" + settlement["networkId"].replace(":", "-")
        + "-height-" + checkpoint["position"]
    )
    if (
        not _minimal_uint(checkpoint.get("position"))
        or checkpoint.get("networkId") != settlement["networkId"]
        or checkpoint.get("genesisHash") != settlement["genesisHash"]
        or checkpoint.get("checkpointId") != expected_checkpoint_id
    ):
        raise ValueError("checkpoint does not match selected rail network")
    agreement_hash = artifact_hash(agreement, "signatures")
    rail_hash = artifact_hash(rail, "signature")
    evidence_hash = artifact_hash(evidence, "signature")
    return {
        "agreement": {
            "contentRef": {
                "kind": "authenticated-fixture",
                "contentHash": agreement_hash,
            },
            "contentHash": agreement_hash,
        },
        "session": {
            "jobId": evidence["jobId"],
            "sessionIdentityHash": hash_value(session),
            "phaseIndex": session["phaseIndex"],
            "phaseKind": session["phaseKind"],
            "roleBindings": {
                "buyer": session["partyClaims"]["buyer"],
                "seller": session["partyClaims"]["seller"],
                "orchestrator": session["phaseOrchestrator"],
                "payer": session["payer"],
                "payee": session["payee"],
            },
            "evaluationPurpose": evaluation_purpose,
        },
        "subject": {
            "settlementEvidenceHash": evidence_hash,
            "transactionSubject": copy.deepcopy(evidence["paymentTxRefs"]),
            "compositeLegId": composite_leg_id,
            "compositeRelationshipHash": composite_relationship_hash,
        },
        "rail": {
            "railDefinitionHash": rail_hash,
            "consumerFinalityProfileHash": hash_value(profile),
            "networkIdentity": {
                "networkId": settlement["networkId"],
                "genesisHash": settlement["genesisHash"],
            },
        },
        "binding": {
            "codec": policy["bindingCodec"],
            "codecVersion": policy["bindingCodecVersion"],
        },
        "resolutionPolicy": {
            "policyId": policy["policyId"],
            "policyVersion": policy["policyVersion"],
            "authorityEpoch": policy["authorityEpoch"],
        },
        "authoritySetHash": hash_value(policy["authorities"]),
        "checkpoint": copy.deepcopy(checkpoint),
        "nonce": nonce,
        "acquisitionBoundary": {
            "issuedAt": issued_at,
            "expiresAt": expires_at,
            "maxObservationAgeMs": policy["maxObservationAgeMs"],
            "clockDomain": policy["acquisitionClock"],
        },
    }


def issue_fixture_authority(
    value: dict,
    base_trusted: dict,
    policy: dict,
    checkpoint: dict,
    *,
    nonce: str,
    issued_at: int | float,
    expires_at: int | float,
    verification_time_ms: int | float,
    policy_source: dict,
    authority_set_source: dict,
    checkpoint_source: dict,
    evaluation_purpose: str = "settlement-finality",
    composite_leg_id: str | None = None,
    composite_relationship_hash: str | None = None,
) -> FinalityResolutionAuthority:
    """Issue one verifier-owned query.  No transported object selects authority."""
    query = derive_query(
        value,
        base_trusted,
        policy,
        checkpoint,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        evaluation_purpose=evaluation_purpose,
        composite_leg_id=composite_leg_id,
        composite_relationship_hash=composite_relationship_hash,
    )
    return FinalityResolutionAuthority(
        authenticated=True,
        policy=copy.deepcopy(policy),
        issued_query=query,
        checkpoint_source=copy.deepcopy(checkpoint_source),
        policy_source=copy.deepcopy(policy_source),
        authority_set_source=copy.deepcopy(authority_set_source),
        base_trusted=copy.deepcopy(base_trusted),
        verification_time_ms=verification_time_ms,
    )


def with_acquisition(
    authority: FinalityResolutionAuthority,
    *,
    records: list[dict],
    retained_responses: list[dict],
    mode: str | None = None,
    replay_value: dict | None = None,
) -> FinalityResolutionAuthority:
    return FinalityResolutionAuthority(
        authenticated=authority.authenticated,
        policy=copy.deepcopy(authority.policy),
        issued_query=copy.deepcopy(authority.issued_query),
        checkpoint_source=copy.deepcopy(authority.checkpoint_source),
        policy_source=copy.deepcopy(authority.policy_source),
        authority_set_source=copy.deepcopy(authority.authority_set_source),
        base_trusted=copy.deepcopy(authority.base_trusted),
        verification_time_ms=authority.verification_time_ms,
        acquisition_records=tuple(copy.deepcopy(records)),
        retained_responses=tuple(copy.deepcopy(retained_responses)),
        mode=authority.mode if mode is None else mode,
        replay_value=copy.deepcopy(
            authority.replay_value if replay_value is None else replay_value
        ),
    )


def _authority_shape(authority: Any) -> bool:
    return (
        is_dataclass(authority)
        and not isinstance(authority, type)
        and authority.__class__.__name__ == "FinalityResolutionAuthority"
        and authority.authenticated is True
        and authority.mode in {"current", "replay"}
        and _policy_shape(authority.policy)
        and isinstance(authority.issued_query, dict)
        and _source_ref(authority.policy_source)
        and _source_ref(authority.authority_set_source)
        and _source_ref(authority.checkpoint_source)
        and isinstance(authority.base_trusted, dict)
        and _finite_time(authority.verification_time_ms)
        and isinstance(authority.acquisition_records, tuple)
        and isinstance(authority.retained_responses, tuple)
        and (authority.replay_value is None or isinstance(authority.replay_value, dict))
    )


def _query_shape(query: Any) -> bool:
    required = {
        "agreement", "session", "subject", "rail", "binding",
        "resolutionPolicy", "authoritySetHash", "checkpoint", "nonce",
        "acquisitionBoundary",
    }
    if not _exact(query, required):
        return False
    agreement = query.get("agreement")
    session = query.get("session")
    subject = query.get("subject")
    rail = query.get("rail")
    binding = query.get("binding")
    resolution = query.get("resolutionPolicy")
    boundary = query.get("acquisitionBoundary")
    checkpoint = query.get("checkpoint")
    if not (
        _exact(agreement, {"contentRef", "contentHash"})
        and _source_ref(agreement.get("contentRef"))
        and agreement["contentRef"]["contentHash"] == agreement.get("contentHash")
        and _exact(session, {
            "jobId", "sessionIdentityHash", "phaseIndex", "phaseKind",
            "roleBindings", "evaluationPurpose",
        })
        and _nonempty(session.get("jobId"))
        and _sha256(session.get("sessionIdentityHash"))
        and isinstance(session.get("phaseIndex"), int)
        and not isinstance(session.get("phaseIndex"), bool)
        and session["phaseIndex"] >= 0
        and _nonempty(session.get("phaseKind"))
        and _exact(session.get("roleBindings"), {
            "buyer", "seller", "orchestrator", "payer", "payee",
        })
        and all(_nonempty(item) for item in session["roleBindings"].values())
        and _nonempty(session.get("evaluationPurpose"))
        and _exact(subject, {
            "settlementEvidenceHash", "transactionSubject", "compositeLegId",
            "compositeRelationshipHash",
        })
        and _sha256(subject.get("settlementEvidenceHash"))
        and isinstance(subject.get("transactionSubject"), list)
        and subject["transactionSubject"]
        and (
            subject.get("compositeLegId") is None
            or _nonempty(subject.get("compositeLegId"))
        )
        and (
            subject.get("compositeRelationshipHash") is None
            or _sha256(subject.get("compositeRelationshipHash"))
        )
        and (subject.get("compositeLegId") is None)
            == (subject.get("compositeRelationshipHash") is None)
        and _exact(rail, {
            "railDefinitionHash", "consumerFinalityProfileHash", "networkIdentity",
        })
        and _sha256(rail.get("railDefinitionHash"))
        and _sha256(rail.get("consumerFinalityProfileHash"))
        and _exact(rail.get("networkIdentity"), {"networkId", "genesisHash"})
        and _nonempty(rail["networkIdentity"].get("networkId"))
        and _sha256(rail["networkIdentity"].get("genesisHash"))
        and binding == {"codec": FIXTURE_BINDING, "codecVersion": "1"}
        and resolution == {
            "policyId": FIXTURE_POLICY_ID,
            "policyVersion": FIXTURE_POLICY_VERSION,
            "authorityEpoch": "fixture-epoch-392-d2",
        }
        and _sha256(query.get("authoritySetHash"))
        and _exact(checkpoint, {
            "checkpointId", "networkId", "genesisHash", "position",
        })
        and _nonempty(checkpoint.get("checkpointId"))
        and _nonempty(checkpoint.get("networkId"))
        and _sha256(checkpoint.get("genesisHash"))
        and _minimal_uint(checkpoint.get("position"))
        and _nonempty(query.get("nonce"))
        and _exact(boundary, {
            "issuedAt", "expiresAt", "maxObservationAgeMs", "clockDomain",
        })
        and _finite_time(boundary.get("issuedAt"))
        and _finite_time(boundary.get("expiresAt"))
        and boundary["issuedAt"] < boundary["expiresAt"]
        and _finite_time(boundary.get("maxObservationAgeMs"))
        and boundary["maxObservationAgeMs"] > 0
        and boundary.get("clockDomain") == "unix-ms"
    ):
        return False
    return True


def _response_shape(response: Any) -> bool:
    required = {
        "finalityObservationResponseVersion", "authorityId", "queryHash",
        "policy", "checkpoint", "signedObservationTime", "response", "signature",
    }
    if not _exact(response, required, {"transportMetadata"}):
        return False
    arm = response.get("response")
    signature = response.get("signature")
    if (
        response.get("finalityObservationResponseVersion") != RESPONSE_VERSION
        or not _nonempty(response.get("authorityId"))
        or not _sha256(response.get("queryHash"))
        or response.get("policy") != {
            "policyId": FIXTURE_POLICY_ID,
            "policyVersion": FIXTURE_POLICY_VERSION,
            "authorityEpoch": "fixture-epoch-392-d2",
        }
        or not _exact(response.get("checkpoint"), {
            "checkpointId", "networkId", "genesisHash", "position",
        })
        or not _finite_time(response.get("signedObservationTime"))
        or not _exact(signature, {"keyId", "algorithm", "value"})
        or not _nonempty(signature.get("keyId"))
        or signature.get("algorithm") != "ed25519"
        or not _nonempty(signature.get("value"))
    ):
        return False
    if not isinstance(arm, dict) or arm.get("status") not in {"observed", "unavailable"}:
        return False
    if arm["status"] == "observed":
        return _exact(arm, {"status", "observation"}) and isinstance(arm.get("observation"), dict)
    return _exact(arm, {"status", "reason"}) and _nonempty(arm.get("reason"))


def _seat(policy: dict, authority_id: str) -> dict | None:
    seats = [item for item in policy["authorities"] if item["authorityId"] == authority_id]
    return seats[0] if len(seats) == 1 else None


def _verify_response_signature(response: dict, seat: dict) -> bool:
    signature = response["signature"]
    keys = [
        key for key in seat["verificationKeys"]
        if key["keyId"] == signature["keyId"]
    ]
    if len(keys) != 1:
        return False
    try:
        raw_key = _b64url(keys[0]["publicKey"])
        raw_signature = _b64url(signature["value"])
        if len(raw_signature) != 64:
            return False
        digest = response_signature_hash(response)
        Ed25519PublicKey.from_public_bytes(raw_key).verify(
            raw_signature, (RESPONSE_DOMAIN + digest).encode("ascii")
        )
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def _acquisition_map(authority: FinalityResolutionAuthority) -> tuple[dict | None, str | None]:
    records = {}
    for record in authority.acquisition_records:
        if not _exact(record, {
            "responseHash", "authorityId", "queryNonce", "acquiredAt", "status",
        }):
            return None, "malformed verifier-local acquisition record"
        if (
            not _sha256(record.get("responseHash"))
            or not _nonempty(record.get("authorityId"))
            or record.get("queryNonce") != authority.issued_query.get("nonce")
            or not _finite_time(record.get("acquiredAt"))
            or record.get("status") != "obtained"
            or record["responseHash"] in records
        ):
            return None, "malformed or duplicate verifier-local acquisition record"
        records[record["responseHash"]] = record
    return records, None


def _projection(observation: dict) -> str:
    """Canonical fixture meaning; signature arrival order is transport-irrelevant."""
    value = copy.deepcopy(observation)

    def normalize(item: Any) -> None:
        if isinstance(item, dict):
            authority = item.get("authorityEvidence")
            if isinstance(authority, dict) and isinstance(authority.get("attestations"), list):
                authority["attestations"].sort(
                    key=lambda row: (
                        row.get("authorityRef", "") if isinstance(row, dict) else "",
                        canonicalize(row),
                    )
                )
            for member in item.values():
                normalize(member)
        elif isinstance(item, list):
            for member in item:
                normalize(member)

    normalize(value)
    return hash_value(value)


def _fixture_checkpoint_relation(
    observation: Any,
    checkpoint: dict,
) -> tuple[str, str]:
    """Bind the registered fixture chain codec to its authenticated head."""
    if not isinstance(observation, dict) or observation.get("kind") != "chain":
        return "indeterminate", "registered fixture checkpoint mapping unavailable"
    native = observation.get("observation")
    if not isinstance(native, dict) or not isinstance(native.get("authenticatedHead"), dict):
        return "error", "malformed fixture observation checkpoint relation"
    expected_id = (
        "fixture-" + checkpoint["networkId"].replace(":", "-")
        + "-height-" + checkpoint["position"]
    )
    if (
        checkpoint.get("checkpointId") != expected_id
        or native.get("networkId") != checkpoint.get("networkId")
        or native.get("genesisHash") != checkpoint.get("genesisHash")
        or native["authenticatedHead"].get("position") != checkpoint.get("position")
    ):
        return "fail", "fixture observation contradicts authenticated checkpoint"
    return "pass", "fixture observation matches authenticated checkpoint"


def _worst_outcome(outcomes: list[dict]) -> dict | None:
    if not outcomes:
        return None
    return max(
        outcomes,
        key=lambda item: (
            DECISION_ORDER.get(item.get("decision"), DECISION_ORDER["error"]),
            canonical_bytes(item),
        ),
    )


def _record_for_replay(
    context: dict,
    authority: FinalityResolutionAuthority,
    union: list[dict],
) -> dict:
    return {
        "finalityResolutionReplayVersion": "1",
        "context": copy.deepcopy(context),
        "policy": copy.deepcopy(authority.policy),
        "policySource": copy.deepcopy(authority.policy_source),
        "authoritySetSource": copy.deepcopy(authority.authority_set_source),
        "checkpointSource": copy.deepcopy(authority.checkpoint_source),
        "acquisitionRecords": copy.deepcopy(list(authority.acquisition_records)),
        "retainedResponses": copy.deepcopy(union),
    }


def _verify_finality_resolution_context(
    value: Any,
    authority: Any,
    *,
    legacy_verifier: Callable[[Any, Any], dict],
    required_mode: str,
) -> dict:
    """Verify complete configured authority coverage and every underlying FV gate."""
    try:
        if not isinstance(value, dict) or set(value) != {"evidence", "rail", "agreement", "context"}:
            return {"decision": "error", "reason": "malformed FV consumer input"}
        context = value.get("context")
        if not _exact(context, {
            "finalityResolutionContextVersion", "capability", "query",
            "responseArtifacts", "replay",
        }):
            return {"decision": "error", "reason": "malformed finality resolution context"}
        if (
            context.get("finalityResolutionContextVersion") != CONTEXT_VERSION
            or context.get("capability") != CAPABILITY
            or not _query_shape(context.get("query"))
            or not isinstance(context.get("responseArtifacts"), list)
            or not isinstance(context.get("replay"), dict)
        ):
            return {"decision": "error", "reason": "malformed finality resolution context"}
        if not _authority_shape(authority):
            return {"decision": "indeterminate", "reason": "verifier-owned resolution authority unavailable"}
        if authority.mode != required_mode:
            return {
                "decision": "indeterminate",
                "reason": "resolution authority mode cannot authorize this operation",
            }
        if context["query"] != authority.issued_query:
            return {"decision": "fail", "reason": "transported query differs from verifier-issued query"}
        expected_query = derive_query(
            value,
            authority.base_trusted,
            authority.policy,
            authority.issued_query["checkpoint"],
            nonce=authority.issued_query["nonce"],
            issued_at=authority.issued_query["acquisitionBoundary"]["issuedAt"],
            expires_at=authority.issued_query["acquisitionBoundary"]["expiresAt"],
            evaluation_purpose=authority.issued_query["session"]["evaluationPurpose"],
            composite_leg_id=authority.issued_query["subject"]["compositeLegId"],
            composite_relationship_hash=authority.issued_query["subject"]["compositeRelationshipHash"],
        )
        if expected_query != authority.issued_query:
            return {"decision": "fail", "reason": "issued query does not bind authenticated commerce inputs"}
        if (
            authority.issued_query["authoritySetHash"] != hash_value(authority.policy["authorities"])
            or authority.issued_query["acquisitionBoundary"]["maxObservationAgeMs"]
                != authority.policy["maxObservationAgeMs"]
            or authority.policy_source.get("contentHash") != hash_value(authority.policy)
            or authority.authority_set_source.get("contentHash")
                != hash_value(authority.policy["authorities"])
            or authority.checkpoint_source.get("contentHash")
                != hash_value(authority.issued_query["checkpoint"])
        ):
            return {"decision": "fail", "reason": "query differs from authenticated resolution policy"}
        expected_replay = {
            "policySource": authority.policy_source,
            "authoritySetSource": authority.authority_set_source,
            "checkpointSource": authority.checkpoint_source,
            "acquisitionRecords": list(authority.acquisition_records),
        }
        if context["replay"] != expected_replay:
            return {"decision": "fail", "reason": "transported replay provenance differs from verifier record"}

        acquisitions, acquisition_error = _acquisition_map(authority)
        if acquisition_error:
            return {"decision": "error", "reason": acquisition_error}
        union_by_bytes = {}
        for response in list(context["responseArtifacts"]) + list(authority.retained_responses):
            if not _response_shape(response):
                return {"decision": "error", "reason": "malformed finality observation response"}
            union_by_bytes[canonical_bytes(response)] = response
        union = [union_by_bytes[key] for key in sorted(union_by_bytes)]
        query_hash = hash_value(authority.issued_query)
        boundary = authority.issued_query["acquisitionBoundary"]
        per_seat = {seat["authorityId"]: [] for seat in authority.policy["authorities"]}
        observed_results = []
        outcomes = []
        for response in union:
            seat = _seat(authority.policy, response["authorityId"])
            if seat is None:
                outcomes.append({
                    "decision": "fail",
                    "reason": "response signer is not a configured authority",
                })
                continue
            if not _verify_response_signature(response, seat):
                outcomes.append({
                    "decision": "fail",
                    "reason": "finality observation response signature does not verify",
                })
                continue
            if (
                response["queryHash"] != query_hash
                or response["policy"] != authority.issued_query["resolutionPolicy"]
                or response["checkpoint"] != authority.issued_query["checkpoint"]
            ):
                continue
            digest = response_hash(response)
            acquisition = acquisitions.get(digest)
            if acquisition is None:
                outcomes.append({
                    "decision": "indeterminate",
                    "reason": "response lacks verifier-local acquisition authority",
                })
                continue
            if acquisition["authorityId"] != response["authorityId"]:
                outcomes.append({
                    "decision": "fail",
                    "reason": "acquisition authority differs from signed responder",
                })
                continue
            if not boundary["issuedAt"] <= acquisition["acquiredAt"] <= boundary["expiresAt"]:
                outcomes.append({
                    "decision": "indeterminate",
                    "reason": "response acquired outside query boundary",
                })
                continue
            if acquisition["acquiredAt"] > authority.verification_time_ms:
                outcomes.append({
                    "decision": "indeterminate",
                    "reason": "response acquired after verifier decision time",
                })
                continue
            if response["signedObservationTime"] > acquisition["acquiredAt"]:
                outcomes.append({
                    "decision": "fail",
                    "reason": "signed observation time is after local acquisition",
                })
                continue
            if acquisition["acquiredAt"] - response["signedObservationTime"] > boundary["maxObservationAgeMs"]:
                outcomes.append({
                    "decision": "indeterminate",
                    "reason": "signed observation expired before acquisition",
                })
                continue
            per_seat[response["authorityId"]].append(response)
            if response["response"]["status"] == "unavailable":
                if response["response"]["reason"] not in authority.policy["unavailableReasons"]:
                    outcomes.append({
                        "decision": "error",
                        "reason": "unregistered unavailable reason",
                    })
                continue
            checkpoint_decision, checkpoint_reason = _fixture_checkpoint_relation(
                response["response"]["observation"],
                authority.issued_query["checkpoint"],
            )
            if checkpoint_decision != "pass":
                outcomes.append({
                    "decision": checkpoint_decision,
                    "reason": checkpoint_reason,
                })
                continue
            candidate = {
                "evidence": value["evidence"],
                "rail": value["rail"],
                "agreement": value["agreement"],
                "context": response["response"]["observation"],
            }
            result = legacy_verifier(candidate, authority.base_trusted)
            observed_results.append((
                response["authorityId"],
                _projection(response["response"]["observation"]),
                result,
            ))
            if result.get("decision") != "pass":
                outcomes.append(result)

        missing = [seat for seat, responses in per_seat.items() if not responses]
        if missing:
            expired = authority.verification_time_ms >= boundary["expiresAt"]
            reason = "query expired with missing configured authority response" if expired else "configured authority acquisition incomplete"
            outcomes.append({
                "decision": "indeterminate",
                "reason": reason,
                "missingAuthorities": missing,
            })
        if any(
            response["response"]["status"] == "unavailable"
            for responses in per_seat.values() for response in responses
        ):
            outcomes.append({
                "decision": "indeterminate",
                "reason": "configured authority explicitly unavailable",
            })
        projections_by_seat = {}
        for authority_id, projection, _ in observed_results:
            projections_by_seat.setdefault(authority_id, set()).add(projection)
        if any(len(projections) != 1 for projections in projections_by_seat.values()):
            outcomes.append({
                "decision": "indeterminate",
                "reason": "one authority supplied unresolved inconsistent observations",
            })
        all_projections = {
            projection for projections in projections_by_seat.values()
            for projection in projections
        }
        if observed_results and len(all_projections) != 1:
            outcomes.append({
                "decision": "indeterminate",
                "reason": "configured authorities supplied conflicting finalized views",
            })
        finality_classes = {result.get("finalityClass") for _, _, result in observed_results}
        if not outcomes and observed_results and (
            len(finality_classes) != 1 or None in finality_classes
        ):
            outcomes.append({
                "decision": "error",
                "reason": "underlying FV class is inconsistent",
            })
        worst = _worst_outcome(outcomes)
        if worst is not None:
            return {
                **worst,
                "replayRecord": _record_for_replay(context, authority, union),
            }
        return {
            "decision": "pass",
            "reason": "complete configured authority coverage and FV verification passed",
            "finalityClass": next(iter(finality_classes)),
            "authorityCount": len(per_seat),
            "replayRecord": _record_for_replay(context, authority, union),
        }
    except (
        ValueError, TypeError, KeyError, IndexError, UnicodeError,
        json.JSONDecodeError, binascii.Error, RecursionError,
    ):
        return {"decision": "error", "reason": "malformed nested finality resolution input"}


def verify_finality_resolution_context(
    value: Any,
    authority: Any,
    *,
    legacy_verifier: Callable[[Any, Any], dict],
) -> dict:
    """Authorize a current decision only with verifier-owned current authority."""
    return _verify_finality_resolution_context(
        value,
        authority,
        legacy_verifier=legacy_verifier,
        required_mode="current",
    )


def replay_finality_resolution(
    replay_record: Any,
    authority: Any,
    *,
    legacy_verifier: Callable[[Any, Any], dict],
) -> dict:
    """Re-evaluate a retained historical record without claiming current finality."""
    if not _exact(replay_record, {
        "finalityResolutionReplayVersion", "context", "policy", "policySource",
        "authoritySetSource", "checkpointSource", "acquisitionRecords",
        "retainedResponses",
    }) or replay_record.get("finalityResolutionReplayVersion") != "1":
        return {"decision": "error", "reason": "malformed finality resolution replay record"}
    if not _authority_shape(authority) or authority.mode != "replay":
        return {"decision": "indeterminate", "reason": "recorded replay authority unavailable"}
    if (
        replay_record["policy"] != authority.policy
        or replay_record["policySource"] != authority.policy_source
        or replay_record["authoritySetSource"] != authority.authority_set_source
        or replay_record["checkpointSource"] != authority.checkpoint_source
        or replay_record["acquisitionRecords"] != list(authority.acquisition_records)
        or replay_record["retainedResponses"] != list(authority.retained_responses)
    ):
        return {"decision": "fail", "reason": "replay record differs from authenticated recorded policy"}
    context = replay_record["context"]
    value = authority.replay_value
    if value is None:
        return {"decision": "indeterminate", "reason": "recorded replay commerce inputs unavailable"}
    candidate = {**copy.deepcopy(value), "context": copy.deepcopy(context)}
    result = _verify_finality_resolution_context(
        candidate,
        authority,
        legacy_verifier=legacy_verifier,
        required_mode="replay",
    )
    return {
        **result,
        "historicalReplay": True,
        "currentFinalityDecision": False,
    }


def verify_composite_resolution(
    legs: Any,
    relationship: Any,
    *,
    legacy_verifier: Callable[[Any, Any], dict],
) -> dict:
    """Apply an independent complete coverage gate to every composite leg."""
    if (
        not isinstance(legs, list)
        or len(legs) < 2
        or not _exact(relationship, {
            "agreementHash", "jobId", "sessionIdentityHash", "phaseIndex",
            "compositeTransactionId", "legIds",
        })
        or not isinstance(relationship.get("legIds"), list)
        or relationship["legIds"] != [leg.get("legId") for leg in legs if isinstance(leg, dict)]
        or any(not _nonempty(leg_id) for leg_id in relationship["legIds"])
        or len(set(relationship["legIds"])) != len(relationship["legIds"])
    ):
        return {"decision": "error", "reason": "malformed composite resolution input"}
    relationship_hash = hash_value(relationship)
    results = []
    for leg_index, leg in enumerate(legs):
        if not _exact(leg, {"legId", "value", "authority"}):
            results.append({
                "decision": "error",
                "reason": "malformed composite leg",
                "legIndex": leg_index,
            })
            continue
        authority = leg["authority"]
        if not _authority_shape(authority):
            results.append({
                "decision": "indeterminate",
                "reason": "composite leg authority unavailable",
                "legId": leg["legId"],
            })
            continue
        query = authority.issued_query
        if not _query_shape(query):
            results.append({
                "decision": "error",
                "reason": "malformed composite leg query",
                "legId": leg["legId"],
            })
            continue
        if (
            query["agreement"]["contentHash"] != relationship["agreementHash"]
            or query["session"]["jobId"] != relationship["jobId"]
            or query["session"]["sessionIdentityHash"] != relationship["sessionIdentityHash"]
            or query["session"]["phaseIndex"] != relationship["phaseIndex"]
            or query["subject"]["compositeLegId"] != leg["legId"]
            or query["subject"]["compositeRelationshipHash"] != relationship_hash
        ):
            results.append({
                "decision": "fail",
                "reason": "composite leg differs from common authenticated relationship",
                "legId": leg["legId"],
            })
            continue
        results.append(verify_finality_resolution_context(
            leg["value"], authority, legacy_verifier=legacy_verifier
        ))
    worst = _worst_outcome(results)
    assert worst is not None
    if worst["decision"] != "pass":
        return {**worst, "legResults": results}
    return {
        "decision": "pass",
        "reason": "every composite leg independently passed complete authority coverage",
        "finalityClass": "profile-final",
        "legResults": results,
    }
