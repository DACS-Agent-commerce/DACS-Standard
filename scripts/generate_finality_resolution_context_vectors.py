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
) -> dict:
    response = {
        "finalityObservationResponseVersion": "1",
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
    return {
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

    vectors = [
        {"name": "complete-all-authorities", "expected": "pass"},
        {"name": "retained-same-authority-conflict", "expected": "indeterminate"},
        {"name": "native-checkpoint-mismatch", "expected": "fail"},
        {"name": "authenticated-economic-contradiction", "expected": "fail"},
        {"name": "configured-authority-unavailable", "expected": "indeterminate"},
        {"name": "signed-time-after-acquisition", "expected": "fail"},
        {"name": "stale-signed-observation", "expected": "indeterminate"},
        {"name": "response-for-other-query", "expected": "indeterminate"},
        {"name": "distinct-composite-legs", "expected": "pass"},
        {"name": "composite-leg-unavailable", "expected": "indeterminate"},
        {"name": "recorded-policy-replay", "expected": "pass"},
    ]
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
            "authority": serialize_authority(authority),
            "want": {
                "decision": "pass",
                "finalityClass": "profile-final",
            },
        },
        "variants": {
            "conflictingResponse": {
                "response": conflict_response,
                "acquisition": acquisition(
                    conflict_response, authority.issued_query["nonce"], ACQUIRED_AT
                ),
            },
            "checkpointMismatchResponse": {
                "response": checkpoint_mismatch_response,
                "acquisition": acquisition(
                    checkpoint_mismatch_response,
                    authority.issued_query["nonce"],
                    ACQUIRED_AT,
                ),
            },
            "contradictoryResponse": {
                "response": contradiction_response,
                "acquisition": acquisition(
                    contradiction_response,
                    authority.issued_query["nonce"],
                    ACQUIRED_AT,
                ),
            },
            "unavailableResponse": {
                "response": unavailable_response,
                "acquisition": acquisition(
                    unavailable_response, authority.issued_query["nonce"], ACQUIRED_AT
                ),
            },
            "futureResponse": {
                "response": future_response,
                "acquisition": acquisition(
                    future_response, authority.issued_query["nonce"], ACQUIRED_AT
                ),
            },
            "staleResponse": {
                "response": stale_response,
                "acquisition": acquisition(
                    stale_response, authority.issued_query["nonce"], ACQUIRED_AT
                ),
            },
            "otherQueryResponse": {
                "response": other_query_response,
                "acquisition": acquisition(
                    other_query_response, authority.issued_query["nonce"], ACQUIRED_AT
                ),
            },
        },
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
