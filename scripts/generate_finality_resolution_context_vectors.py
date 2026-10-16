#!/usr/bin/env python3
"""Generate deterministic #392 D2 all-authority resolution fixtures."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from scripts.finality_resolution_context_reference import (
        CAPABILITY,
        CONTEXT_VERSION,
        RESPONSE_DOMAIN,
        artifact_hash,
        fixture_policy,
        hash_value,
        issue_fixture_authority,
        response_hash,
        response_signature_hash,
        with_acquisition,
    )
    from scripts.generate_settlement_finality_verification_vectors import (
        FixtureFactory,
        OBSERVED_AT,
        nonminimal_b64u,
    )
    from scripts.jcs import canonicalize
except ImportError:
    from finality_resolution_context_reference import (
        CAPABILITY,
        CONTEXT_VERSION,
        RESPONSE_DOMAIN,
        artifact_hash,
        fixture_policy,
        hash_value,
        issue_fixture_authority,
        response_hash,
        response_signature_hash,
        with_acquisition,
    )
    from generate_settlement_finality_verification_vectors import (
        FixtureFactory,
        OBSERVED_AT,
        nonminimal_b64u,
    )
    from jcs import canonicalize


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "finality-resolution-context-v1.json"
)
JOB_ID = "01K50M2V4W8Z7J6N5P3T1H9GQC"
ISSUED_AT = 1_900_000_000_000
ACQUIRED_AT = 1_900_000_005_000
EXPIRES_AT = 1_900_000_006_000
VERIFICATION_TIME = 1_900_000_010_000
AUTHORITY_SEEDS = {
    "observer-a-key": "91" * 32,
    "observer-b-key": "a2" * 32,
}


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def source_ref(label: str, value: object) -> dict:
    del label
    return {
        "kind": "authenticated-fixture",
        "contentHash": hashlib.sha256(
            canonicalize(value).encode("utf-8")
        ).hexdigest(),
    }


def signed_response(
    key: Ed25519PrivateKey,
    *,
    authority_id: str,
    key_id: str,
    query: dict,
    checkpoint: dict,
    arm: dict,
    signed_time: int | float = OBSERVED_AT,
    transport_metadata: dict | None = None,
    version: str = "1",
    extra_members: dict | None = None,
) -> dict:
    response = {
        "finalityObservationResponseVersion": version,
        "authorityId": authority_id,
        "queryHash": hash_value(query),
        "policy": copy.deepcopy(query["resolutionPolicy"]),
        "checkpoint": copy.deepcopy(checkpoint),
        "signedObservationTime": signed_time,
        "response": copy.deepcopy(arm),
        "signature": {
            "keyId": key_id,
            "algorithm": "ed25519",
            "value": "",
        },
    }
    if transport_metadata is not None:
        response["transportMetadata"] = copy.deepcopy(transport_metadata)
    response.update(copy.deepcopy(extra_members or {}))
    digest = response_signature_hash(response)
    response["signature"]["value"] = b64u(
        key.sign((RESPONSE_DOMAIN + digest).encode("ascii"))
    )
    return response


def acquisition(response: dict, nonce: str, acquired_at: int | float) -> dict:
    return {
        "responseHash": response_hash(response),
        "authorityId": response["authorityId"],
        "queryNonce": nonce,
        "acquiredAt": acquired_at,
        "status": "obtained",
    }


def checkpoint_for(observation: dict) -> dict:
    chain = observation["observation"]
    return {
        "checkpointId": (
            "fixture-" + chain["networkId"].replace(":", "-")
            + "-height-" + chain["authenticatedHead"]["position"]
        ),
        "networkId": chain["networkId"],
        "genesisHash": chain["genesisHash"],
        "position": chain["authenticatedHead"]["position"],
    }


def serialize_authority(authority) -> dict:
    payload = {
        "authenticated": authority.authenticated,
        "policy": authority.policy,
        "issuedQuery": authority.issued_query,
        "checkpointSource": authority.checkpoint_source,
        "policySource": authority.policy_source,
        "authoritySetSource": authority.authority_set_source,
        "verificationTimeMs": authority.verification_time_ms,
        "acquisitionRecords": list(authority.acquisition_records),
        "retainedResponses": list(authority.retained_responses),
    }
    if authority.mode != "current":
        payload["mode"] = authority.mode
        payload["replayValue"] = authority.replay_value
    return payload


def build_authority(
    base_value: dict,
    base_trusted: dict,
    policy: dict,
    checkpoint: dict,
    *,
    nonce: str,
    policy_source: dict,
    authority_set_source: dict,
    checkpoint_source: dict,
    leg_id: str | None = None,
    relationship_hash: str | None = None,
):
    return issue_fixture_authority(
        base_value,
        base_trusted,
        policy,
        checkpoint,
        nonce=nonce,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        verification_time_ms=VERIFICATION_TIME,
        policy_source=policy_source,
        authority_set_source=authority_set_source,
        checkpoint_source=checkpoint_source,
        composite_leg_id=leg_id,
        composite_relationship_hash=relationship_hash,
    )


def context_for(authority, responses: list[dict]) -> dict:
    return {
        "finalityResolutionContextVersion": CONTEXT_VERSION,
        "capability": CAPABILITY,
        "query": copy.deepcopy(authority.issued_query),
        "responseArtifacts": copy.deepcopy(responses),
        "replay": {
            "policySource": copy.deepcopy(authority.policy_source),
            "authoritySetSource": copy.deepcopy(authority.authority_set_source),
            "checkpointSource": copy.deepcopy(authority.checkpoint_source),
            "acquisitionRecords": copy.deepcopy(list(authority.acquisition_records)),
        },
    }


def resolved_input(
    base_value: dict,
    authority,
    transported: list[dict],
    retained: list[dict],
    records: list[dict],
) -> dict:
    """Materialize one case as the exact `positive`-shaped verifier input."""
    authority = with_acquisition(
        authority, records=records, retained_responses=retained
    )
    value = {
        "evidence": copy.deepcopy(base_value["evidence"]),
        "rail": copy.deepcopy(base_value["rail"]),
        "agreement": copy.deepcopy(base_value["agreement"]),
        "context": context_for(authority, transported),
    }
    return {"value": value, "authority": serialize_authority(authority)}


def replace_seat(
    value: dict, payload: dict, variant: dict, authority_id: str
) -> dict:
    """Replace one seat's transported, retained and acquired response."""
    value = copy.deepcopy(value)
    payload = copy.deepcopy(payload)
    response = copy.deepcopy(variant["response"])
    value["context"]["responseArtifacts"] = [
        item for item in value["context"]["responseArtifacts"]
        if item["authorityId"] != authority_id
    ] + [response]
    payload["retainedResponses"] = [
        item for item in payload["retainedResponses"]
        if item["authorityId"] != authority_id
    ] + [copy.deepcopy(response)]
    payload["acquisitionRecords"] = [
        item for item in payload["acquisitionRecords"]
        if item["authorityId"] != authority_id
    ] + [copy.deepcopy(variant["acquisition"])]
    value["context"]["replay"]["acquisitionRecords"] = copy.deepcopy(
        payload["acquisitionRecords"]
    )
    return {"value": value, "authority": payload}


def replay_record(value: dict, payload: dict) -> dict:
    """The FRC-9 record a current decision retains for later replay."""
    union = {
        canonicalize(response): response
        for response in (
            value["context"]["responseArtifacts"] + payload["retainedResponses"]
        )
    }
    return {
        "finalityResolutionReplayVersion": "1",
        "context": copy.deepcopy(value["context"]),
        "policy": copy.deepcopy(payload["policy"]),
        "policySource": copy.deepcopy(payload["policySource"]),
        "authoritySetSource": copy.deepcopy(payload["authoritySetSource"]),
        "checkpointSource": copy.deepcopy(payload["checkpointSource"]),
        "acquisitionRecords": copy.deepcopy(payload["acquisitionRecords"]),
        "retainedResponses": [
            copy.deepcopy(union[key])
            for key in sorted(union, key=lambda item: item.encode("utf-8"))
        ],
    }


def document() -> dict:
    factory = FixtureFactory()
    base_value = factory.model_input("block-depth", job_id=JOB_ID)
    base_value["rail"]["consumerFinalityProfile"][
        "finalityResolutionCapability"
    ] = CAPABILITY
    factory.rebind_rail(base_value)
    base_trusted = copy.deepcopy(factory.trusted)
    keys = {
        key_id: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
        for key_id, seed in AUTHORITY_SEEDS.items()
    }
    policy = fixture_policy([
        {
            "authorityId": "observer-a",
            "verificationKeys": [{
                "keyId": "observer-a-key",
                "algorithm": "ed25519",
                "publicKey": b64u(keys["observer-a-key"].public_key().public_bytes_raw()),
            }],
        },
        {
            "authorityId": "observer-b",
            "verificationKeys": [{
                "keyId": "observer-b-key",
                "algorithm": "ed25519",
                "publicKey": b64u(keys["observer-b-key"].public_key().public_bytes_raw()),
            }],
        },
    ])
    observation = copy.deepcopy(base_value["context"])
    checkpoint = checkpoint_for(observation)
    policy_source = source_ref("policy", policy)
    authority_set_source = source_ref("authority-set", policy["authorities"])
    checkpoint_source = source_ref("checkpoint", checkpoint)
    authority = build_authority(
        base_value,
        base_trusted,
        policy,
        checkpoint,
        nonce="fixture-query-nonce-392-d2",
        policy_source=policy_source,
        authority_set_source=authority_set_source,
        checkpoint_source=checkpoint_source,
    )
    response_a = signed_response(
        keys["observer-a-key"],
        authority_id="observer-a",
        key_id="observer-a-key",
        query=authority.issued_query,
        checkpoint=checkpoint,
        arm={"status": "observed", "observation": observation},
        transport_metadata={"arrivalSequence": 2, "channel": "fixture-a"},
    )
    equivalent = copy.deepcopy(observation)
    equivalent["observation"]["authorityEvidence"]["attestations"].reverse()
    response_b = signed_response(
        keys["observer-b-key"],
        authority_id="observer-b",
        key_id="observer-b-key",
        query=authority.issued_query,
        checkpoint=checkpoint,
        arm={"status": "observed", "observation": equivalent},
        transport_metadata={"arrivalSequence": 1, "channel": "fixture-b"},
    )
    records = [
        acquisition(response_b, authority.issued_query["nonce"], ACQUIRED_AT - 250),
        acquisition(response_a, authority.issued_query["nonce"], ACQUIRED_AT),
    ]
    authority = with_acquisition(
        authority,
        records=records,
        retained_responses=[response_a, response_b],
    )
    value = {
        "evidence": copy.deepcopy(base_value["evidence"]),
        "rail": copy.deepcopy(base_value["rail"]),
        "agreement": copy.deepcopy(base_value["agreement"]),
        "context": context_for(authority, [response_b, response_a]),
    }

    profile = base_value["rail"]["consumerFinalityProfile"]["settlement"]
    reference = base_value["evidence"]["paymentTxRefs"][0]
    event_bytes = observation["observation"]["selectedEventProof"]["eventBytes"]
    event = json.loads(base64.urlsafe_b64decode(
        event_bytes + "=" * (-len(event_bytes) % 4)
    ))
    conflicting_observation = {
        "kind": "chain",
        "observation": factory.chain_observation(
            profile, reference, event, "d2-conflicting-view"
        ),
    }
    conflict_response = signed_response(
        keys["observer-a-key"],
        authority_id="observer-a",
        key_id="observer-a-key",
        query=authority.issued_query,
        checkpoint=checkpoint,
        arm={"status": "observed", "observation": conflicting_observation},
    )
    # A sibling of the canonical inclusion block re-includes the transaction,
    # so its head is a competing block at the pinned checkpoint height.  Both
    # fork views have complete native proofs and pinned RPC signatures; only
    # which authenticated head is canonical remains unresolved.
    fork_observation = {
        "kind": "chain",
        "observation": factory.chain_observation(
            profile, reference, event, "d2-reorg-replacement",
            parent_id=observation["observation"]["inclusionBlock"]["parentId"],
        ),
    }
    conflicting_head_response = signed_response(
        keys["observer-b-key"],
        authority_id="observer-b",
        key_id="observer-b-key",
        query=authority.issued_query,
        checkpoint=checkpoint,
        arm={"status": "observed", "observation": fork_observation},
    )
    conflicting_heads_input = resolved_input(
        base_value,
        authority,
        [response_a, conflicting_head_response],
        [response_a, conflicting_head_response],
        [
            acquisition(response_a, authority.issued_query["nonce"], ACQUIRED_AT),
            acquisition(
                conflicting_head_response, authority.issued_query["nonce"], ACQUIRED_AT
            ),
        ],
    )
    # After the reorganisation both authorities report the replacement fork.
    # The verifier retained observer-a's earlier canonical-fork response; the
    # transported set omits it.  Later signing or acquisition is not a winner.
    reorg_responses = [
        signed_response(
            keys[key_id],
            authority_id=authority_id,
            key_id=key_id,
            query=authority.issued_query,
            checkpoint=checkpoint,
            arm={"status": "observed", "observation": fork_observation},
            signed_time=OBSERVED_AT + 1,
        )
        for authority_id, key_id in (
            ("observer-a", "observer-a-key"),
            ("observer-b", "observer-b-key"),
        )
    ]
    reorg_input = resolved_input(
        base_value,
        authority,
        reorg_responses,
        [response_a] + reorg_responses,
        [acquisition(response_a, authority.issued_query["nonce"], ACQUIRED_AT)] + [
            acquisition(response, authority.issued_query["nonce"], ACQUIRED_AT + 1 + index)
            for index, response in enumerate(reorg_responses)
        ],
    )
    checkpoint_mismatch_observation = {
        "kind": "chain",
        "observation": factory.chain_observation(
            profile,
            reference,
            event,
            "d2-other-checkpoint",
            head_position=112,
        ),
    }
    checkpoint_mismatch_response = signed_response(
        keys["observer-a-key"],
        authority_id="observer-a",
        key_id="observer-a-key",
        query=authority.issued_query,
        checkpoint=checkpoint,
        arm={
            "status": "observed",
            "observation": checkpoint_mismatch_observation,
        },
    )
    contradictory_value = copy.deepcopy(base_value)
    factory.rebuild_observation_event(
        contradictory_value,
        ("observation",),
        lambda event: event.__setitem__("amount", "6"),
    )
    contradiction_response = signed_response(
        keys["observer-a-key"],
        authority_id="observer-a",
        key_id="observer-a-key",
        query=authority.issued_query,
        checkpoint=checkpoint,
        arm={
            "status": "observed",
            "observation": contradictory_value["context"],
        },
    )
    unavailable_response = signed_response(
        keys["observer-b-key"],
        authority_id="observer-b",
        key_id="observer-b-key",
        query=authority.issued_query,
        checkpoint=checkpoint,
        arm={"status": "unavailable", "reason": "maintenance"},
        signed_time=ACQUIRED_AT - 100,
    )
    future_response = signed_response(
        keys["observer-a-key"],
        authority_id="observer-a",
        key_id="observer-a-key",
        query=authority.issued_query,
        checkpoint=checkpoint,
        arm={"status": "observed", "observation": observation},
        signed_time=ACQUIRED_AT + 1,
    )
    stale_response = signed_response(
        keys["observer-a-key"],
        authority_id="observer-a",
        key_id="observer-a-key",
        query=authority.issued_query,
        checkpoint=checkpoint,
        arm={"status": "observed", "observation": observation},
        signed_time=ACQUIRED_AT - policy["maxObservationAgeMs"] - 1,
    )
    other_query = copy.deepcopy(authority.issued_query)
    other_query["nonce"] = "another-verifier-query"
    other_query_response = signed_response(
        keys["observer-b-key"],
        authority_id="observer-b",
        key_id="observer-b-key",
        query=other_query,
        checkpoint=checkpoint,
        arm={"status": "observed", "observation": observation},
    )

    session = base_trusted["sessionAuthorityByJob"][JOB_ID]
    relationship = {
        "agreementHash": artifact_hash(base_value["agreement"], "signatures"),
        "jobId": JOB_ID,
        "sessionIdentityHash": hash_value(session),
        "phaseIndex": session["phaseIndex"],
        "compositeTransactionId": "fixture-composite-transaction-392-d2",
        "legIds": ["source", "destination"],
    }
    relationship_hash = hash_value(relationship)
    source_leg_value = copy.deepcopy(base_value)
    destination_leg_value = copy.deepcopy(base_value)
    destination_profile = destination_leg_value["rail"][
        "consumerFinalityProfile"
    ]["settlement"]
    destination_profile["requiredDepth"] = 13
    destination_reference = copy.deepcopy(reference)
    destination_reference["txHash"] = factory.tx_id("d2-composite-destination")
    destination_event = factory.common_event(destination_reference, session)
    destination_leg_value["context"] = {
        "kind": "chain",
        "observation": factory.chain_observation(
            destination_profile,
            destination_reference,
            destination_event,
            "d2-composite-destination",
            head_position=113,
        ),
    }
    destination_leg_value["evidence"]["paymentTxRefs"] = [
        copy.deepcopy(destination_reference)
    ]
    destination_leg_value["evidence"]["settlementFinality"][
        "finalityBlocks"
    ] = destination_profile["requiredDepth"]
    factory.rebind_rail(destination_leg_value)
    composite_values = {
        "source": source_leg_value,
        "destination": destination_leg_value,
    }
    composite_legs = []
    for index, leg_id in enumerate(relationship["legIds"]):
        leg_value = composite_values[leg_id]
        leg_observation = leg_value["context"]
        leg_checkpoint = checkpoint_for(leg_observation)
        leg_checkpoint_source = source_ref("checkpoint", leg_checkpoint)
        leg_authority = build_authority(
            leg_value,
            base_trusted,
            policy,
            leg_checkpoint,
            nonce="fixture-composite-%s-392-d2" % leg_id,
            policy_source=policy_source,
            authority_set_source=authority_set_source,
            checkpoint_source=leg_checkpoint_source,
            leg_id=leg_id,
            relationship_hash=relationship_hash,
        )
        leg_responses = [
            signed_response(
                keys[key_id],
                authority_id=authority_id,
                key_id=key_id,
                query=leg_authority.issued_query,
                checkpoint=leg_checkpoint,
                arm={"status": "observed", "observation": leg_observation},
                transport_metadata={"leg": leg_id, "seat": authority_id},
            )
            for authority_id, key_id in (
                ("observer-a", "observer-a-key"),
                ("observer-b", "observer-b-key"),
            )
        ]
        leg_records = [
            acquisition(
                response,
                leg_authority.issued_query["nonce"],
                ACQUIRED_AT + index * 50 + response_index,
            )
            for response_index, response in enumerate(leg_responses)
        ]
        leg_authority = with_acquisition(
            leg_authority,
            records=leg_records,
            retained_responses=leg_responses,
        )
        resolved_leg_value = {
            "evidence": copy.deepcopy(leg_value["evidence"]),
            "rail": copy.deepcopy(leg_value["rail"]),
            "agreement": copy.deepcopy(leg_value["agreement"]),
            "context": context_for(leg_authority, leg_responses),
        }
        leg_entry = {
            "legId": leg_id,
            "value": resolved_leg_value,
            "authority": serialize_authority(leg_authority),
        }
        if leg_id == "destination":
            leg_unavailable = signed_response(
                keys["observer-b-key"],
                authority_id="observer-b",
                key_id="observer-b-key",
                query=leg_authority.issued_query,
                checkpoint=leg_checkpoint,
                arm={"status": "unavailable", "reason": "maintenance"},
                signed_time=ACQUIRED_AT - 100,
            )
            leg_entry["unavailableVariant"] = {
                "response": leg_unavailable,
                "acquisition": acquisition(
                    leg_unavailable,
                    leg_authority.issued_query["nonce"],
                    ACQUIRED_AT,
                ),
            }
        composite_legs.append(leg_entry)

    strong_case = factory.strong_bundle_case(
        "block-depth", job_id=JOB_ID, value=base_value
    )
    strong_case["pointer"] = factory.pointer(strong_case["bundle"])
    finality_ref = next(iter(
        strong_case["authority"]["finalityVerificationByCanonicalRef"]
    ))
    strong_case["authority"]["finalityVerificationByCanonicalRef"][finality_ref] = (
        copy.deepcopy(value)
    )

    # Every case is materialized as the exact verifier input so a third party
    # can execute it from the JSON alone; ``positive`` and ``variants`` remain
    # as the building blocks the focused tests mutate.
    positive_payload = serialize_authority(authority)
    nonce = authority.issued_query["nonce"]
    variants = {
        "conflictingResponse": {
            "response": conflict_response,
            "acquisition": acquisition(conflict_response, nonce, ACQUIRED_AT),
        },
        "checkpointMismatchResponse": {
            "response": checkpoint_mismatch_response,
            "acquisition": acquisition(
                checkpoint_mismatch_response, nonce, ACQUIRED_AT
            ),
        },
        "contradictoryResponse": {
            "response": contradiction_response,
            "acquisition": acquisition(contradiction_response, nonce, ACQUIRED_AT),
        },
        "unavailableResponse": {
            "response": unavailable_response,
            "acquisition": acquisition(unavailable_response, nonce, ACQUIRED_AT),
        },
        "futureResponse": {
            "response": future_response,
            "acquisition": acquisition(future_response, nonce, ACQUIRED_AT),
        },
        "staleResponse": {
            "response": stale_response,
            "acquisition": acquisition(stale_response, nonce, ACQUIRED_AT),
        },
        "otherQueryResponse": {
            "response": other_query_response,
            "acquisition": acquisition(other_query_response, nonce, ACQUIRED_AT),
        },
    }
    retained_conflict_payload = copy.deepcopy(positive_payload)
    retained_conflict_payload["retainedResponses"].append(
        copy.deepcopy(conflict_response)
    )
    retained_conflict_payload["acquisitionRecords"].append(
        copy.deepcopy(variants["conflictingResponse"]["acquisition"])
    )
    retained_conflict_value = copy.deepcopy(value)
    retained_conflict_value["context"]["replay"]["acquisitionRecords"] = (
        copy.deepcopy(retained_conflict_payload["acquisitionRecords"])
    )
    composite_relationship_input = {
        "relationship": copy.deepcopy(relationship),
        "legs": [
            {
                "legId": leg["legId"],
                "value": copy.deepcopy(leg["value"]),
                "authority": copy.deepcopy(leg["authority"]),
            }
            for leg in composite_legs
        ],
    }
    unavailable_leg_input = copy.deepcopy(composite_relationship_input)
    destination = composite_legs[1]
    unavailable_leg = replace_seat(
        destination["value"], destination["authority"],
        destination["unavailableVariant"], "observer-b",
    )
    unavailable_leg_input["legs"][1].update(unavailable_leg)
    replay_payload = with_acquisition(
        authority,
        records=positive_payload["acquisitionRecords"],
        retained_responses=replay_record(value, positive_payload)["retainedResponses"],
        mode="replay",
        replay_value=value,
    )

    # FRC-1: the signed profile selects the capability, so neither the
    # positive single-view observation nor #416's competing fork view may
    # be verified through the historical single-view contract.
    single_view_value = copy.deepcopy(value)
    single_view_value["context"] = copy.deepcopy(
        response_a["response"]["observation"]
    )
    fork_view_value = copy.deepcopy(conflicting_heads_input["value"])
    fork_view_value["context"] = copy.deepcopy(
        conflicting_head_response["response"]["observation"]
    )
    # FRC-1: a resolution context under a signed profile that does not
    # select the capability is refused before its query is compared.
    uncapable = copy.deepcopy(base_value)
    del uncapable["rail"]["consumerFinalityProfile"]["finalityResolutionCapability"]
    factory.rebind_rail(uncapable)
    uncapable_value = {
        "evidence": copy.deepcopy(uncapable["evidence"]),
        "rail": copy.deepcopy(uncapable["rail"]),
        "agreement": copy.deepcopy(uncapable["agreement"]),
        "context": copy.deepcopy(value["context"]),
    }
    # FRC-8: a genuinely signed observer-a response of an unknown version.
    unknown_version_response = signed_response(
        keys["observer-a-key"],
        authority_id="observer-a",
        key_id="observer-a-key",
        query=authority.issued_query,
        checkpoint=checkpoint,
        arm={"status": "observed", "observation": observation},
        transport_metadata={"arrivalSequence": 2, "channel": "fixture-a"},
        version="2",
    )
    unknown_version_input = replace_seat(
        value,
        positive_payload,
        {
            "response": unknown_version_response,
            "acquisition": acquisition(
                unknown_version_response, nonce, ACQUIRED_AT
            ),
        },
        "observer-a",
    )
    # FRC-8: the response arm is a closed observed/unavailable union.
    unknown_status_response = signed_response(
        keys["observer-a-key"],
        authority_id="observer-a",
        key_id="observer-a-key",
        query=authority.issued_query,
        checkpoint=checkpoint,
        arm={"status": "finalized", "observation": observation},
        transport_metadata={"arrivalSequence": 2, "channel": "fixture-a"},
    )
    unknown_status_input = replace_seat(
        value,
        positive_payload,
        {
            "response": unknown_status_response,
            "acquisition": acquisition(
                unknown_status_response, nonce, ACQUIRED_AT
            ),
        },
        "observer-a",
    )
    # FRC-2: the query was issued for the signed evidence E1; a second
    # genuinely signed evidence E2 for the same transaction is presented.
    other_evidence_value = copy.deepcopy(value)
    other_evidence_value["evidence"]["observedAt"] = OBSERVED_AT + 1
    factory.resign_evidence(other_evidence_value["evidence"])

    def verify_input(case_value: dict, payload: dict) -> dict:
        return {"value": copy.deepcopy(case_value), "authority": copy.deepcopy(payload)}

    # FRC-8: the response and both arms are closed member sets.  Each
    # response is genuinely signed and acquired; only one member is extra.
    def closed_member_input(authority_id: str, arm: dict, **options) -> dict:
        response = signed_response(
            keys[authority_id + "-key"],
            authority_id=authority_id,
            key_id=authority_id + "-key",
            query=authority.issued_query,
            checkpoint=checkpoint,
            arm=arm,
            **options,
        )
        return replace_seat(
            value, positive_payload,
            {"response": response, "acquisition": acquisition(response, nonce, ACQUIRED_AT)},
            authority_id,
        )

    response_extra_member_input = closed_member_input(
        "observer-a", {"status": "observed", "observation": observation},
        transport_metadata={"arrivalSequence": 2, "channel": "fixture-a"},
        extra_members={"finalityHint": "final"},
    )
    observed_arm_extra_member_input = closed_member_input(
        "observer-a",
        {"status": "observed", "observation": observation, "finalityHint": "final"},
        transport_metadata={"arrivalSequence": 2, "channel": "fixture-a"},
    )
    unavailable_arm_extra_member_input = closed_member_input(
        "observer-b",
        {"status": "unavailable", "reason": "maintenance", "retryAfterMs": 1000},
        signed_time=ACQUIRED_AT - 100,
    )
    # FRC-8: the one optional member is typed `object`; a signed scalar or
    # null in its place is outside the closed type.
    transport_metadata_scalar_input = closed_member_input(
        "observer-a", {"status": "observed", "observation": observation},
        transport_metadata=7,
    )
    transport_metadata_null_input = closed_member_input(
        "observer-a", {"status": "observed", "observation": observation},
        extra_members={"transportMetadata": None},
    )
    # FRC-8: observer-b's view carries only the threshold's two RPC
    # signatures where observer-a's carries all three.  Both are sufficient
    # authentication of one head, path, transaction and event.
    threshold_observation = copy.deepcopy(observation)
    threshold_attestations = threshold_observation["observation"]["authorityEvidence"]["attestations"]
    threshold_attestations[:] = threshold_attestations[:profile["observation"]["threshold"]]
    threshold_set_input = closed_member_input(
        "observer-b", {"status": "observed", "observation": threshold_observation},
        transport_metadata={"arrivalSequence": 1, "channel": "fixture-b"},
    )

    # FRC-5: each verifier-local acquisition record names the issued nonce,
    # an obtained status, one response hash and the signed responder.
    def with_records(mutate) -> dict:
        payload = copy.deepcopy(positive_payload)
        mutate(payload["acquisitionRecords"])
        case_value = copy.deepcopy(value)
        case_value["context"]["replay"]["acquisitionRecords"] = copy.deepcopy(
            payload["acquisitionRecords"]
        )
        return verify_input(case_value, payload)

    def observer_a_record(records: list) -> dict:
        return next(item for item in records if item["authorityId"] == "observer-a")

    other_nonce_input = with_records(
        lambda records: observer_a_record(records).__setitem__("queryNonce", "fixture-query-nonce-other")
    )
    not_obtained_input = with_records(
        lambda records: observer_a_record(records).__setitem__("status", "failed")
    )
    duplicate_record_input = with_records(
        lambda records: records.append(copy.deepcopy(observer_a_record(records)))
    )
    other_responder_input = with_records(
        lambda records: observer_a_record(records).__setitem__("authorityId", "observer-b")
    )

    # FV entry: malformed verifier-owned policy material is error, not missing.
    malformed_policy_payload = copy.deepcopy(positive_payload)
    malformed_policy_payload["policy"]["authorities"][0]["verificationKeys"][0][
        "publicKey"
    ] = "not-a-key"

    # FRC-9: the replay record's version discriminator is closed.
    unknown_replay = replay_record(value, positive_payload)
    unknown_replay["finalityResolutionReplayVersion"] = "2"

    # FRC-4 / CORE SIG-6: observer-a's response signature value changes and
    # the verifier records the response as it acquired it.
    def observer_a_signature(signature_value) -> dict:
        case_value = copy.deepcopy(value)
        payload = copy.deepcopy(positive_payload)
        acquired_hash = None
        for container in (case_value["context"]["responseArtifacts"], payload["retainedResponses"]):
            for response in container:
                if response["authorityId"] == "observer-a":
                    response["signature"]["value"] = signature_value(response["signature"]["value"])
                    acquired_hash = response_hash(response)
        observer_a_record(payload["acquisitionRecords"])["responseHash"] = acquired_hash
        case_value["context"]["replay"]["acquisitionRecords"] = copy.deepcopy(
            payload["acquisitionRecords"]
        )
        return verify_input(case_value, payload)

    nonminimal_signature_input = observer_a_signature(nonminimal_b64u)
    invalid_signature_input = observer_a_signature(lambda _: b64u(bytes(range(64))))

    # FRC-2: the transported query is not the one the verifier issued.
    transported_query_value = copy.deepcopy(value)
    transported_query_value["context"]["query"]["nonce"] = "fixture-query-nonce-transported"

    # FRC-2: the verifier's own policy source record does not hash the policy.
    policy_source_payload = copy.deepcopy(positive_payload)
    policy_source_payload["policySource"]["contentHash"] = "00" * 32
    policy_source_value = copy.deepcopy(value)
    policy_source_value["context"]["replay"]["policySource"] = copy.deepcopy(
        policy_source_payload["policySource"]
    )

    # FRC-5: local acquisition time against the query boundary and the
    # verifier decision time.
    outside_boundary_input = with_records(
        lambda records: observer_a_record(records).__setitem__(
            "acquiredAt", EXPIRES_AT + 1
        )
    )
    after_decision_payload = copy.deepcopy(positive_payload)
    after_decision_payload["verificationTimeMs"] = min(
        record["acquiredAt"] for record in positive_payload["acquisitionRecords"]
    ) - 1

    # FRC-9: a replay authority without its recorded commerce inputs.
    replay_without_value = copy.deepcopy(serialize_authority(replay_payload))
    replay_without_value["replayValue"] = None

    # FV entry: each structural rule of the verifier-owned policy is error.
    def malformed_policy(mutate) -> dict:
        payload = copy.deepcopy(positive_payload)
        mutate(payload["policy"])
        return verify_input(value, payload)

    def seat(index):
        return lambda policy: policy["authorities"][index]

    policy_cases = [
        ("resolution-authority-policy-authorities-empty",
         "the authenticated verifier-owned policy configures no authority",
         lambda policy: policy.__setitem__("authorities", [])),
        ("resolution-authority-policy-duplicate-authority-id",
         "two seats of the authenticated verifier-owned policy share one authorityId",
         lambda policy: seat(1)(policy).__setitem__("authorityId", seat(0)(policy)["authorityId"])),
        ("resolution-authority-policy-duplicate-key-id",
         "one seat lists the same verification key twice",
         lambda policy: seat(0)(policy)["verificationKeys"].append(copy.deepcopy(seat(0)(policy)["verificationKeys"][0]))),
        ("resolution-authority-policy-seat-without-keys",
         "one seat of the authenticated verifier-owned policy has no verification key",
         lambda policy: seat(0)(policy).__setitem__("verificationKeys", [])),
        ("resolution-authority-policy-key-algorithm-unknown",
         "one seat key names an unregistered algorithm",
         lambda policy: seat(0)(policy)["verificationKeys"][0].__setitem__("algorithm", "secp256k1")),
        ("resolution-authority-policy-unavailable-reasons-duplicate",
         "the policy lists one unavailable reason twice",
         lambda policy: policy["unavailableReasons"].append(policy["unavailableReasons"][0])),
    ]

    # FV entry on the replay and composite entry points.
    malformed_replay_authority = copy.deepcopy(serialize_authority(replay_payload))
    malformed_replay_authority["policy"]["authorities"][0]["verificationKeys"][0][
        "publicKey"
    ] = "not-a-key"
    malformed_leg_input = copy.deepcopy(composite_relationship_input)
    malformed_leg_input["legs"][1]["authority"]["policy"]["authorities"][0][
        "verificationKeys"
    ][0]["publicKey"] = "not-a-key"

    vectors = [
        {"name": "complete-all-authorities", "expected": "pass",
         "operation": "verify",
         "note": "both configured authorities sign the same native view for the "
                 "verifier-issued query; transport order and metadata differ",
         "input": verify_input(value, positive_payload)},
        {"name": "retained-same-authority-conflict", "expected": "indeterminate",
         "operation": "verify",
         "note": "a retained, separately acquired observer-a response with a "
                 "different native view conflicts with the transported one",
         "input": verify_input(retained_conflict_value, retained_conflict_payload)},
        {"name": "fv-conflicting-authenticated-heads", "expected": "indeterminate",
         "operation": "verify",
         "note": "two configured authorities sign individually valid views whose "
                 "heads are competing sibling-fork blocks at the checkpoint height",
         "input": conflicting_heads_input},
        {"name": "fv-reorg-unresolved", "expected": "indeterminate",
         "operation": "verify",
         "note": "a retained pre-reorganisation response conflicts with the same "
                 "authority's later replacement-fork response; both authorities "
                 "agree on the replacement and transport omits the retained view",
         "input": reorg_input},
        {"name": "native-checkpoint-mismatch", "expected": "fail",
         "operation": "verify",
         "note": "observer-a's signed native head is not at the pinned checkpoint",
         "input": replace_seat(
             value, positive_payload,
             variants["checkpointMismatchResponse"], "observer-a",
         )},
        {"name": "authenticated-economic-contradiction", "expected": "fail",
         "operation": "verify",
         "note": "observer-a's signed native event contradicts the signed "
                 "agreement amount",
         "input": replace_seat(
             value, positive_payload,
             variants["contradictoryResponse"], "observer-a",
         )},
        {"name": "configured-authority-unavailable", "expected": "indeterminate",
         "operation": "verify",
         "note": "observer-b signs an explicit registered unavailable response",
         "input": replace_seat(
             value, positive_payload,
             variants["unavailableResponse"], "observer-b",
         )},
        {"name": "signed-time-after-acquisition", "expected": "fail",
         "operation": "verify",
         "note": "observer-a's signed observation time is after the verifier's "
                 "local acquisition",
         "input": replace_seat(
             value, positive_payload, variants["futureResponse"], "observer-a",
         )},
        {"name": "stale-signed-observation", "expected": "indeterminate",
         "operation": "verify",
         "note": "observer-a's signed observation is older than the policy's "
                 "maximum age at acquisition",
         "input": replace_seat(
             value, positive_payload, variants["staleResponse"], "observer-a",
         )},
        {"name": "response-for-other-query", "expected": "indeterminate",
         "operation": "verify",
         "note": "observer-b's only response answers another query, so its "
                 "configured seat stays empty",
         "input": replace_seat(
             value, positive_payload, variants["otherQueryResponse"], "observer-b",
         )},
        {"name": "distinct-composite-legs", "expected": "pass",
         "operation": "verify-composite",
         "note": "each leg passes its own complete authority gate under its own "
                 "profile, subject and checkpoint",
         "input": composite_relationship_input},
        {"name": "composite-leg-unavailable", "expected": "indeterminate",
         "operation": "verify-composite",
         "note": "the destination leg's observer-b seat is explicitly unavailable",
         "input": unavailable_leg_input},
        {"name": "recorded-policy-replay", "expected": "pass",
         "operation": "replay",
         "note": "the recorded replay authority re-evaluates the retained record; "
                 "the result is historical, not a current finality decision",
         "input": {
             "replayRecord": replay_record(value, positive_payload),
             "authority": serialize_authority(replay_payload),
         }},
        {"name": "frc1-single-view-under-capability", "expected": "error",
         "operation": "verify",
         "note": "the signed profile selects finality-resolution-context-v1; a "
                 "single-view chain context is refused, never verified as a "
                 "historical single-view input",
         "input": verify_input(single_view_value, positive_payload)},
        {"name": "frc1-fork-view-under-capability", "expected": "error",
         "operation": "verify",
         "note": "presenting only observer-b's competing-fork view from "
                 "fv-conflicting-authenticated-heads cannot bypass the conflict "
                 "through the single-view contract",
         "input": verify_input(
             fork_view_value, conflicting_heads_input["authority"]
         )},
        {"name": "frc1-context-without-signed-capability", "expected": "error",
         "operation": "verify",
         "note": "the steward re-signed the rail without the capability; a "
                 "resolution context cannot be consumed under that profile",
         "input": verify_input(uncapable_value, positive_payload)},
        {"name": "response-version-unknown", "expected": "error",
         "operation": "verify",
         "note": "observer-a genuinely signs and the verifier acquires a response "
                 "whose finalityObservationResponseVersion is \"2\"",
         "input": unknown_version_input},
        {"name": "response-status-unknown", "expected": "error",
         "operation": "verify",
         "note": "observer-a genuinely signs and the verifier acquires a response "
                 "whose arm status is outside observed/unavailable",
         "input": unknown_status_input},
        {"name": "issued-query-other-evidence", "expected": "fail",
         "operation": "verify",
         "note": "the query was issued for one signed evidence record; another "
                 "validly signed evidence for the same transaction is presented "
                 "with that query and its responses",
         "input": verify_input(other_evidence_value, positive_payload)},
        {"name": "response-extra-member", "expected": "error",
         "operation": "verify",
         "note": "observer-a genuinely signs and the verifier acquires a response "
                 "carrying an extra top-level member",
         "input": response_extra_member_input},
        {"name": "response-observed-arm-extra-member", "expected": "error",
         "operation": "verify",
         "note": "observer-a genuinely signs and the verifier acquires an observed "
                 "arm carrying an extra member",
         "input": observed_arm_extra_member_input},
        {"name": "response-unavailable-arm-extra-member", "expected": "error",
         "operation": "verify",
         "note": "observer-b genuinely signs and the verifier acquires an "
                 "unavailable arm carrying an extra member",
         "input": unavailable_arm_extra_member_input},
        {"name": "response-transport-metadata-not-object", "expected": "error",
         "operation": "verify",
         "note": "observer-a genuinely signs and the verifier acquires a response "
                 "whose optional transportMetadata is the integer 7",
         "input": transport_metadata_scalar_input},
        {"name": "response-transport-metadata-null", "expected": "error",
         "operation": "verify",
         "note": "observer-a genuinely signs and the verifier acquires a response "
                 "whose optional transportMetadata is null",
         "input": transport_metadata_null_input},
        {"name": "equivalent-sufficient-authentication-sets", "expected": "pass",
         "operation": "verify",
         "note": "observer-a's view carries three RPC signatures and observer-b's "
                 "the threshold's two over the same head, path, transaction and "
                 "event; which sufficient set authenticates a view is not a "
                 "finality conflict",
         "input": threshold_set_input},
        {"name": "acquisition-record-other-nonce", "expected": "error",
         "operation": "verify",
         "note": "observer-a's verifier-local acquisition record names another "
                 "query nonce than the issued query",
         "input": other_nonce_input},
        {"name": "acquisition-record-not-obtained", "expected": "error",
         "operation": "verify",
         "note": "observer-a's verifier-local acquisition record status is not "
                 "obtained",
         "input": not_obtained_input},
        {"name": "acquisition-record-duplicate-response-hash", "expected": "error",
         "operation": "verify",
         "note": "two verifier-local acquisition records name observer-a's "
                 "response hash",
         "input": duplicate_record_input},
        {"name": "acquisition-authority-differs-from-responder", "expected": "fail",
         "operation": "verify",
         "note": "the verifier-local acquisition record for observer-a's signed "
                 "response names observer-b",
         "input": other_responder_input},
        {"name": "resolution-authority-policy-malformed", "expected": "error",
         "operation": "verify",
         "note": "the authenticated verifier-owned policy names a seat key that is "
                 "not a 32-byte Base64URL value",
         "input": verify_input(value, malformed_policy_payload)},
        {"name": "replay-record-version-unknown", "expected": "error",
         "operation": "replay",
         "note": "the retained replay record's finalityResolutionReplayVersion "
                 "is \"2\"",
         "input": {
             "replayRecord": unknown_replay,
             "authority": serialize_authority(replay_payload),
         }},
        {"name": "response-signature-nonminimal-base64url", "expected": "fail",
         "operation": "verify",
         "note": "observer-a's response signature decodes to the genuine bytes but "
                 "is not the minimal Base64URL spelling; the verifier acquired it "
                 "as transported",
         "input": nonminimal_signature_input},
        {"name": "response-signature-invalid", "expected": "fail",
         "operation": "verify",
         "note": "observer-a's response carries a well-formed signature over other "
                 "bytes; the verifier acquired it as transported",
         "input": invalid_signature_input},
        {"name": "transported-query-differs", "expected": "fail",
         "operation": "verify",
         "note": "the transported query names another nonce than the query the "
                 "verifier issued",
         "input": verify_input(transported_query_value, positive_payload)},
        {"name": "resolution-policy-source-differs", "expected": "fail",
         "operation": "verify",
         "note": "the verifier's policy source record does not hash the "
                 "authenticated policy it holds",
         "input": verify_input(policy_source_value, policy_source_payload)},
        {"name": "response-acquired-outside-query-boundary", "expected": "indeterminate",
         "operation": "verify",
         "note": "the verifier-local record acquires observer-a's response after "
                 "the issued query expired",
         "input": outside_boundary_input},
        {"name": "response-acquired-after-decision-time", "expected": "indeterminate",
         "operation": "verify",
         "note": "the verifier decision time precedes every local acquisition",
         "input": verify_input(value, after_decision_payload)},
        {"name": "replay-commerce-inputs-unavailable", "expected": "indeterminate",
         "operation": "replay",
         "note": "the recorded replay authority lacks its recorded commerce inputs",
         "input": {
             "replayRecord": replay_record(value, positive_payload),
             "authority": replay_without_value,
         }},
        {"name": "replay-authority-policy-malformed", "expected": "error",
         "operation": "replay",
         "note": "the recorded replay authority's policy names a seat key that is "
                 "not a 32-byte Base64URL value",
         "input": {
             "replayRecord": replay_record(value, positive_payload),
             "authority": malformed_replay_authority,
         }},
        {"name": "composite-leg-authority-policy-malformed", "expected": "error",
         "operation": "verify-composite",
         "note": "the destination leg's verifier-owned policy names a seat key "
                 "that is not a 32-byte Base64URL value",
         "input": malformed_leg_input},
    ]
    vectors.extend(
        {"name": name, "expected": "error", "operation": "verify", "note": note,
         "input": malformed_policy(mutate)}
        for name, note, mutate in policy_cases
    )
    return {
        "set": "finality-resolution-context-v1",
        "tier": "candidate",
        "spec": "DACS-4 #392 D2 finality resolution context version 1",
        "count": len(vectors),
        "hash": hashlib.sha256(json.dumps(
            vectors,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")).hexdigest(),
        "vectors": vectors,
        "fixtureOnly": True,
        "authorityCount": len(policy["authorities"]),
        "baseTrusted": base_trusted,
        "positive": {
            "value": value,
            "authority": positive_payload,
            "want": {
                "decision": "pass",
                "finalityClass": "profile-final",
            },
        },
        "variants": variants,
        "composite": {
            "relationship": relationship,
            "legs": composite_legs,
            "want": {"decision": "pass"},
        },
        "dacs5Consumer": strong_case,
    }


def render() -> bytes:
    return (json.dumps(document(), indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.write:
        OUTPUT.write_bytes(expected)
        return 0
    if not OUTPUT.exists() or OUTPUT.read_bytes() != expected:
        print("%s is stale; run this generator with --write" % OUTPUT)
        return 1
    print("finality resolution context vector is deterministic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
