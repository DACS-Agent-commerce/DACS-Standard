#!/usr/bin/env python3
"""Generate DACS-5 v0.6 authenticated reputation-window vectors."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from jcs import canonicalize as jcs_canonicalize


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "reputation-authenticated-window-v0.6.json"
)
SET_NAME = "reputation-authenticated-window-v0.6"
SPEC = "DACS-5 v0.6 §10.5 AWT-1..AWT-8 authenticated outcome window"

JOB_ID = "01K4AWT0000000000000000001"
ANCHOR_TRANSACTION_REF = {"kind": "demos-tx", "value": "tx-window-a"}
SELLER_ANCHOR_TRANSACTION_REF = {
    "kind": "demos-tx", "value": "tx-window-seller"
}
LEGACY_PROFILE_COMMIT = "3426faaebc09948d57a3a6d30fd6795df579b68f"
TRUSTED_ERA_POLICY = {
    "policyId": "dacs-test-era-policy-v1",
    "adapter": "conformance-harness-profile-era-v1",
    "authority": "did:demos:steward",
    "producer": "did:demos:legacy-reputation-producer",
    "sessionId": JOB_ID,
    "profile": "dacs-next-dacs-5-v0.5",
    "commit": LEGACY_PROFILE_COMMIT,
    "currentProfile": "dacs-next-dacs-5-v0.6",
    "revisionRelation": "predates-current",
}
TRUSTED_OUTCOME_POLICY = {
    "policyId": "dacs-test-outcome-binding-v1",
    "adapter": "fixture-only-completed-job-binding-projection-v1",
    "trustSource": "conformance-harness-fixture-only",
    "proofProfile": "exact-job-pipeline-terminal-evidence-native-event",
    "historyOrder": "native-order-then-sha256-jcs-ascending",
}

BUNDLE = {
    "substrate": "demos:testnet",
    "logicalAddress": "stor-" + "11" * 32,
    "nativeAddress": "storage-program:window-bundle-a",
    "contentHash": "22" * 32,
    "writer": "demos1buyer",
    "nonce": "7",
    "transactionRef": copy.deepcopy(ANCHOR_TRANSACTION_REF),
    "jobId": JOB_ID,
    "outcome": "completed",
}
SELLER_BUNDLE = {
    **copy.deepcopy(BUNDLE),
    "logicalAddress": "stor-" + "33" * 32,
    "nativeAddress": "storage-program:window-bundle-seller",
    "writer": "demos1seller",
    "nonce": "8",
    "transactionRef": copy.deepcopy(SELLER_ANCHOR_TRANSACTION_REF),
}
PIPELINE = {
    "listingId": "01K4AWT-LISTING-00000000001",
    "listingVersion": "1",
    "phases": [
        {"phaseIndex": 0, "kind": "pay-x402"},
        {"phaseIndex": 1, "kind": "deliver-attested-payload"},
    ],
}
TERMINAL_PHASE_EVIDENCE = [
    {
        "jobId": JOB_ID,
        "phaseIndex": 0,
        "phaseKind": "pay-x402",
        "evidenceRef": {
            "anchor": {"kind": "demos-storage", "locator": "evidence-payment"},
            "contentHash": "44" * 32,
        },
    },
    {
        "jobId": JOB_ID,
        "phaseIndex": 1,
        "phaseKind": "deliver-attested-payload",
        "evidenceRef": {
            "anchor": {"kind": "demos-storage", "locator": "evidence-delivery"},
            "contentHash": "55" * 32,
        },
    },
]
OUTCOME_BINDING_OBJECTS = {
    "sessionOutcome": {
        "jobId": JOB_ID,
        "bundleContentHash": BUNDLE["contentHash"],
        "outcome": "completed",
    },
    "listingPipeline": copy.deepcopy(PIPELINE),
    "terminalPhaseEvidence": copy.deepcopy(TERMINAL_PHASE_EVIDENCE),
}

LEGACY_DISCRIMINATORS = (
    "derivationVersion",
    "replayableDerivationVersion",
    "jobBoundReplayableDerivationVersion",
    "settlementVerifiedDerivationVersion",
    "replayableSettlementVerifiedDerivationVersion",
)
REPLAYABLE_LEGACY_DISCRIMINATORS = {
    "replayableDerivationVersion",
    "jobBoundReplayableDerivationVersion",
    "replayableSettlementVerifiedDerivationVersion",
}

OUTCOME_FIXTURES = {
    "fixture-outcome-0999": (999, 9, "tx-job-complete-0999", "0"),
    "fixture-outcome-1000": (1_000, 10, "tx-job-complete-1000", "0"),
    "fixture-outcome-2000": (2_000, 20, "tx-job-complete-2000", "0"),
    # A second authenticated adapter observation of the same native event gives
    # replay a non-trivial, canonically ordered evidence history.
    "fixture-outcome-2000-secondary": (
        2_000, 20, "tx-job-complete-2000", "0"
    ),
    "fixture-outcome-2100-conflict": (
        2_100, 21, "tx-job-complete-conflict", "1"
    ),
    "fixture-outcome-3000": (3_000, 30, "tx-job-complete-3000", "0"),
    "fixture-outcome-3001": (3_001, 31, "tx-job-complete-3001", "0"),
}


def jcs_hash(value: object) -> str:
    return hashlib.sha256(jcs_canonicalize(value).encode("utf-8")).hexdigest()


def transaction_ref(value: str) -> dict:
    return {"kind": "demos-tx", "value": value}


def receipt_projection_hash(item: dict) -> str:
    scope = {key: value for key, value in item.items() if key != "evidence"}
    return jcs_hash(scope)


def seal_receipt(item: dict) -> dict:
    item["evidence"] = {
        "kind": "fixture-only-anchor-binding-adapter-projection",
        "value": receipt_projection_hash(item),
    }
    return item


def receipt(
    transaction: str = "tx-window-a",
    timestamp: int | None = 7_000,
    *,
    state: str = "finalized",
    disposition: str = "established",
    block_id: str = "block-20",
    native_order: int = 20,
    bundle: dict | None = None,
    preserved_receipt: dict | None = None,
) -> dict:
    bound_bundle = BUNDLE if bundle is None else bundle
    item = {
        "receiptVersion": "1",
        **{
            field: copy.deepcopy(bound_bundle[field])
            for field in (
                "substrate", "logicalAddress", "nativeAddress", "contentHash",
                "writer", "nonce",
            )
        },
        "finalityProfile": "demos-bft-final",
        "transactionRef": transaction_ref(transaction),
        "state": state,
        "observationDisposition": disposition,
        "observedAt": 9_999_999,
        "nativeOrder": native_order,
    }
    if state in {"included", "finalized"}:
        item["blockRef"] = {"id": block_id, "height": str(native_order)}
        if timestamp is not None:
            item["blockRef"]["timestamp"] = timestamp
    if disposition == "indeterminate" and preserved_receipt is not None:
        item["preservedReceiptHash"] = jcs_hash(preserved_receipt)
    return seal_receipt(item)


def relation_proof_ref(predecessor: dict, replacement: dict, native_order: int) -> str:
    return "fixture-only-replacement:" + jcs_hash({
        "predecessor": predecessor,
        "replacement": replacement,
        "nativeOrder": native_order,
    })


def replacement_receipt(
    transaction: str = "tx-window-a",
    replacement: str = "tx-window-b",
    *,
    native_order: int = 18,
    relation_valid: bool = True,
    bundle: dict | None = None,
) -> dict:
    item = receipt(
        transaction,
        state="replaced",
        timestamp=None,
        native_order=native_order,
        bundle=bundle,
    )
    predecessor_ref = transaction_ref(transaction)
    replacement_ref = transaction_ref(replacement)
    proof_ref = relation_proof_ref(
        predecessor_ref, replacement_ref, native_order
    )
    if not relation_valid:
        proof_ref = "fixture-only-replacement:unverified"
    item["replacementTransactionRef"] = replacement_ref
    item["replacementRelation"] = {
        "kind": "fixture-only-authenticated-replacement-projection",
        "predecessor": predecessor_ref,
        "replacement": copy.deepcopy(replacement_ref),
        "proofRef": proof_ref,
    }
    return seal_receipt(item)


def mutate_receipt(item: dict, mutator) -> dict:
    changed = copy.deepcopy(item)
    mutator(changed)
    return seal_receipt(changed)


def canonical_history(items: list[dict]) -> list[dict]:
    unique = {jcs_hash(item): item for item in items}
    return [
        copy.deepcopy(item)
        for digest, item in sorted(
            unique.items(),
            key=lambda pair: (pair[1]["nativeOrder"], pair[0]),
        )
    ]


def canonical_outcome_history(items: list[dict]) -> list[dict]:
    unique = {jcs_hash(item): item for item in items}
    return [
        copy.deepcopy(item)
        for digest, item in sorted(
            unique.items(),
            key=lambda pair: (pair[1]["nativeEvent"]["nativeOrder"], pair[0]),
        )
    ]


def outcome_object_hashes(objects: dict | None = None) -> dict:
    source = OUTCOME_BINDING_OBJECTS if objects is None else objects
    return {
        "sessionOutcome": jcs_hash(source["sessionOutcome"]),
        "listingPipeline": jcs_hash(source["listingPipeline"]),
        "terminalPhaseEvidence": jcs_hash(source["terminalPhaseEvidence"]),
    }


def outcome_time_evidence(proof_ref: str = "fixture-outcome-2000") -> dict:
    timestamp, native_order, transaction, event_index = OUTCOME_FIXTURES[proof_ref]
    return {
        "projectionVersion": "1",
        "kind": "fixture-only-binding-adapter-outcome-time",
        "policyId": TRUSTED_OUTCOME_POLICY["policyId"],
        "proofRef": proof_ref,
        "objectHashes": outcome_object_hashes(),
        "nativeEvent": {
            "kind": "fixture-only-job-outcome-event",
            "transactionRef": transaction_ref(transaction),
            "eventIndex": event_index,
            "nativeOrder": native_order,
            "timestamp": timestamp,
            "jobId": JOB_ID,
            "outcome": "completed",
            "bundleContentHash": BUNDLE["contentHash"],
        },
    }


def current_input(
    receipts: list[dict] | None = None,
    outcome_evidence: list[dict] | None = None,
    **changes,
) -> dict:
    item = {
        "derivationDiscriminators": {
            "authenticatedWindowDerivationVersion": "1"
        },
        "windowingBasis": "verified-business-outcome-occurrence",
        "windowStart": 1_000,
        "windowEnd": 3_000,
        "bundleFinalisedAt": 8_000_000,
        "sessionRecordEndedAt": 1,
        "bundle": copy.deepcopy(BUNDLE),
        "knownReceipts": copy.deepcopy([receipt()] if receipts is None else receipts),
        "outcomeTimePolicy": copy.deepcopy(TRUSTED_OUTCOME_POLICY),
        "outcomeBindingObjects": copy.deepcopy(OUTCOME_BINDING_OBJECTS),
        "knownOutcomeTimeEvidence": copy.deepcopy(
            [outcome_time_evidence()] if outcome_evidence is None else outcome_evidence
        ),
        "replayContext": None,
        "historicalPolicy": False,
        "trustedEraPolicy": None,
        "eraEvidence": None,
    }
    item.update(copy.deepcopy(changes))
    return item


def replay_input(
    receipts: list[dict],
    outcome_evidence: list[dict],
) -> dict:
    anchor_history = canonical_history(receipts)
    outcome_history = canonical_outcome_history(outcome_evidence)
    return current_input(
        receipts,
        outcome_evidence,
        replayContext={
            "outcomeTimePolicy": TRUSTED_OUTCOME_POLICY["policyId"],
            "anchorReceipt": copy.deepcopy(anchor_history[-1]),
            "anchorReceiptHistory": anchor_history,
            "outcomeTimeEvidence": copy.deepcopy(outcome_history[0]),
            "outcomeTimeEvidenceHistory": outcome_history,
        },
    )


def attestation_ref(content_hash: str = BUNDLE["contentHash"]) -> dict:
    return {
        "anchor": {"kind": "demos-storage", "locator": "bundle-a"},
        "contentHash": content_hash,
    }


def historical_resolution_context(discriminator: str) -> list[dict]:
    entry = {
        "contentHash": BUNDLE["contentHash"],
        "resolvedRole": "buyer",
        "roleEvidence": {
            "kind": "address", "resolvedAddress": BUNDLE["logicalAddress"]
        },
        "counterpartyDisposition": "present",
        "counterpartyRef": attestation_ref(),
        "counterpartyRoleEvidence": {
            "kind": "address", "resolvedAddress": SELLER_BUNDLE["logicalAddress"]
        },
    }
    if discriminator in {
        "jobBoundReplayableDerivationVersion",
        "replayableSettlementVerifiedDerivationVersion",
    }:
        entry["resolvedJobId"] = JOB_ID
    return [entry]


def historical_derivation(discriminator: str) -> dict:
    item = {
        discriminator: "1",
        "partyPrimaryClaim": {
            "scheme": "key", "identifier": "demos1buyer", "parameters": {}
        },
        "windowStart": 1_000,
        "windowEnd": 3_000,
        "bundleCount": 1,
        "metrics": {
            "completionRate": 1,
            "counterpartyAdjustedCompletionRate": 1,
            "counterpartyFaultRate": 0,
            "averageBuyerRating": None,
            "averageSellerRating": 5,
            "observedTransactionalVolume": [
                {"amount": "10", "currency": "USDC"}
            ],
            "transactionCountByCurrency": [{"currency": "USDC", "count": 1}],
        },
        "computedAt": 3_100,
        "windowingBasis": "finalisedAt",
        "bundleRefs": [attestation_ref()],
    }
    if discriminator in REPLAYABLE_LEGACY_DISCRIMINATORS:
        item["resolutionContext"] = historical_resolution_context(discriminator)
    return item


def verified_era_evidence(discriminator: str) -> dict:
    return {
        "kind": "verified-profile-era-projection",
        "verificationDisposition": "verified",
        **copy.deepcopy(TRUSTED_ERA_POLICY),
        "derivationHash": jcs_hash(historical_derivation(discriminator)),
    }


def historical_input(discriminator: str, *, verified: bool) -> dict:
    return {
        "derivationDiscriminators": {discriminator: "1"},
        "historicalDerivation": historical_derivation(discriminator),
        "historicalPolicy": verified,
        "trustedEraPolicy": copy.deepcopy(TRUSTED_ERA_POLICY) if verified else None,
        "eraEvidence": verified_era_evidence(discriminator) if verified else None,
    }


def want(
    *, countable: bool, member: bool, timestamp: int | None,
    current: bool = True, historical: bool = False,
) -> dict:
    return {
        "currentProfile": current,
        "historicalEligible": historical,
        "timeDisposition": "verified" if countable else "indeterminate",
        "countable": countable,
        "windowMember": member,
        "windowTimestamp": timestamp,
        "clockSource": (
            "outcomeTimeEvidence.nativeEvent.timestamp" if countable else None
        ),
    }


def vector(name: str, expected: str, note: str, input_data: dict, output: dict) -> dict:
    return {
        "name": name,
        "expected": expected,
        "note": note,
        "input": input_data,
        "want": output,
    }


def build_vectors() -> list[dict]:
    verified = want(countable=True, member=True, timestamp=2_000)
    outside_early = want(countable=True, member=False, timestamp=999)
    outside_late = want(countable=True, member=False, timestamp=3_001)
    indeterminate = want(countable=False, member=False, timestamp=None)
    vectors = [
        vector(
            "awt-canonical-outcome-pass", "pass",
            "the fixture adapter proves the exact multi-phase job outcome occurrence",
            current_input(), verified,
        ),
        vector(
            "awt-delayed-anchor-does-not-refresh-old-outcome", "pass",
            "an in-window bundle publication cannot refresh an old business outcome",
            current_input([receipt(timestamp=2_000)], outcome_evidence=[outcome_time_evidence("fixture-outcome-0999")]),
            outside_early,
        ),
        vector(
            "awt-early-anchor-does-not-exclude-recent-outcome", "pass",
            "bundle publication time does not replace verified business occurrence",
            current_input([receipt(timestamp=999)]), verified,
        ),
        vector(
            "awt-late-anchor-does-not-exclude-recent-outcome", "pass",
            "delayed audit finalization does not move a verified recent outcome",
            current_input([receipt(timestamp=3_001)]), verified,
        ),
        vector(
            "awt-producer-finalised-at-does-not-control-window", "pass",
            "producer finalisedAt is audit metadata and supplies no occurrence authority",
            current_input(bundleFinalisedAt=999), verified,
        ),
        vector(
            "awt-session-ended-at-does-not-control-window", "pass",
            "the off-chain SessionRecord clock supplies no occurrence authority",
            current_input(sessionRecordEndedAt=9_000_000), verified,
        ),
        vector(
            "awt-window-start-equality-inclusive", "pass",
            "verified occurrence exactly equal to windowStart is included",
            current_input(outcome_evidence=[outcome_time_evidence("fixture-outcome-1000")]),
            want(countable=True, member=True, timestamp=1_000),
        ),
        vector(
            "awt-window-end-equality-inclusive", "pass",
            "verified occurrence exactly equal to windowEnd is included",
            current_input(outcome_evidence=[outcome_time_evidence("fixture-outcome-3000")]),
            want(countable=True, member=True, timestamp=3_000),
        ),
        vector(
            "awt-outcome-after-window-is-not-member", "pass",
            "a verified occurrence after the inclusive upper bound is excluded",
            current_input(outcome_evidence=[outcome_time_evidence("fixture-outcome-3001")]),
            outside_late,
        ),
        vector(
            "awt-buyer-copy-publication-date-is-inert", "pass",
            "one session occurrence is unchanged by buyer and seller publication dates",
            current_input([
                receipt(timestamp=500),
                receipt(
                    "tx-window-seller", timestamp=9_000,
                    bundle=SELLER_BUNDLE, native_order=90, block_id="block-90",
                ),
            ]),
            verified,
        ),
        vector(
            "awt-seller-copy-publication-date-is-inert", "pass",
            "selecting the other reconciled copy leaves session-wide membership unchanged",
            current_input(
                [
                    receipt(timestamp=500),
                    receipt(
                        "tx-window-seller", timestamp=9_000,
                        bundle=SELLER_BUNDLE, native_order=90, block_id="block-90",
                    ),
                ],
                bundle=copy.deepcopy(SELLER_BUNDLE),
            ),
            verified,
        ),
        vector(
            "awt-finalized-anchor-without-timestamp-pass", "pass",
            "anchor finality proves provenance but does not supply the business clock",
            current_input([receipt(timestamp=None)]), verified,
        ),
        vector(
            "awt-missing-anchor-receipt-indeterminate", "indeterminate",
            "missing selected-bundle provenance keeps the current job non-countable",
            current_input([]), indeterminate,
        ),
        vector(
            "awt-accepted-anchor-is-not-final", "indeterminate",
            "durable acceptance does not establish required bundle finality",
            current_input([receipt(state="accepted", timestamp=None)]), indeterminate,
        ),
        vector(
            "awt-included-anchor-without-finality-insufficient", "indeterminate",
            "non-final inclusion cannot establish selected-bundle provenance",
            current_input([receipt(state="included")]), indeterminate,
        ),
        vector(
            "awt-invalid-anchor-adapter-proof-indeterminate", "indeterminate",
            "unauthenticated anchor projection is discarded and cannot prove provenance",
            current_input([{**receipt(), "evidence": {"kind": "bad", "value": "bad"}}]),
            indeterminate,
        ),
    ]

    for field, value in (
        ("substrate", "other:testnet"),
        ("logicalAddress", "stor-" + "66" * 32),
        ("nativeAddress", "storage-program:other"),
        ("contentHash", "77" * 32),
        ("writer", "demos1attacker"),
        ("nonce", "9"),
    ):
        mismatched = mutate_receipt(
            receipt(), lambda item, f=field, v=value: item.__setitem__(f, v)
        )
        vectors.append(vector(
            f"awt-anchor-{field.lower()}-mismatch-indeterminate", "indeterminate",
            f"the finalized receipt does not bind the selected bundle's {field}",
            current_input([mismatched]), indeterminate,
        ))

    replaced = replacement_receipt()
    successor = receipt("tx-window-b", native_order=21, block_id="block-21")
    invalid_relation = replacement_receipt(relation_valid=False)
    reversed_relation = copy.deepcopy(replaced)
    reversed_relation["replacementTransactionRef"] = transaction_ref("tx-window-a")
    reversed_relation["replacementRelation"] = {
        "kind": "fixture-only-authenticated-replacement-projection",
        "predecessor": transaction_ref("tx-window-b"),
        "replacement": transaction_ref("tx-window-a"),
        "proofRef": relation_proof_ref(
            transaction_ref("tx-window-b"), transaction_ref("tx-window-a"), 18
        ),
    }
    reversed_relation = seal_receipt(reversed_relation)
    vectors += [
        vector(
            "awt-wrong-sole-anchor-transaction-indeterminate", "indeterminate",
            "an unrelated finalized transaction does not prove selected-bundle provenance",
            current_input([receipt("tx-unrelated")]), indeterminate,
        ),
        vector(
            "awt-replaced-original-without-final-successor", "indeterminate",
            "a replaced transaction is inert until its successor independently finalizes",
            current_input([replaced]), indeterminate,
        ),
        vector(
            "awt-finalized-successor-without-authenticated-edge", "indeterminate",
            "an unverified replacement relation cannot authorize its finalized successor",
            current_input([invalid_relation, successor]), indeterminate,
        ),
        vector(
            "awt-reversed-replacement-edge-indeterminate", "indeterminate",
            "a reversed predecessor-successor relation cannot authorize finality",
            current_input([reversed_relation, successor]), indeterminate,
        ),
        vector(
            "awt-finalized-exact-replacement-pass", "pass",
            "a CORE-valid replacement edge precedes the successor's own final receipt",
            current_input([replaced, successor]), verified,
        ),
        vector(
            "awt-two-hop-replacement-pass", "pass",
            "ordered A-to-B-to-C replacement with independent C finality remains valid",
            current_input([
                replacement_receipt(),
                replacement_receipt("tx-window-b", "tx-window-c", native_order=19),
                receipt("tx-window-c", native_order=21, block_id="block-21"),
            ]),
            verified,
        ),
        vector(
            "awt-late-replacement-edge-indeterminate", "indeterminate",
            "the replacement edge must strictly precede successor finalization",
            current_input([
                replacement_receipt(native_order=22),
                receipt("tx-window-b", native_order=21, block_id="block-21"),
            ]),
            indeterminate,
        ),
        vector(
            "awt-equal-order-replacement-edge-indeterminate", "indeterminate",
            "equal native order does not prove that replacement preceded finality",
            current_input([
                replacement_receipt(native_order=21),
                receipt("tx-window-b", native_order=21, block_id="block-21"),
            ]),
            indeterminate,
        ),
        vector(
            "awt-finalized-predecessor-then-replaced-indeterminate", "indeterminate",
            "a transaction that finalized can never later become replaced",
            current_input([
                receipt(native_order=17, block_id="block-17"),
                replacement_receipt(native_order=18),
                successor,
            ]),
            indeterminate,
        ),
        vector(
            "awt-replaced-predecessor-then-finalized-indeterminate", "indeterminate",
            "a replaced transaction cannot later transition to finalized",
            current_input([
                replaced,
                receipt(native_order=19, block_id="block-19"),
                successor,
            ]),
            indeterminate,
        ),
        vector(
            "awt-cyclic-replacement-history-indeterminate", "indeterminate",
            "A-to-B-to-A replacement cannot authorize a finalized cycle member",
            current_input([
                replacement_receipt(),
                replacement_receipt("tx-window-b", "tx-window-a", native_order=19),
                receipt(native_order=21, block_id="block-21"),
            ]),
            indeterminate,
        ),
        vector(
            "awt-branching-replacement-history-indeterminate", "indeterminate",
            "one predecessor cannot authorize two replacement successors",
            current_input([
                replacement_receipt(replacement="tx-window-b", native_order=18),
                replacement_receipt(replacement="tx-window-c", native_order=19),
                receipt("tx-window-b", native_order=21, block_id="block-21"),
                receipt("tx-window-c", native_order=22, block_id="block-22"),
            ]),
            indeterminate,
        ),
        vector(
            "awt-replacement-successor-not-final-indeterminate", "indeterminate",
            "the successor must carry its own independently verified final receipt",
            current_input([
                replaced,
                receipt("tx-window-b", state="included", native_order=21),
            ]),
            indeterminate,
        ),
        vector(
            "awt-reorg-without-finalized-reentry", "indeterminate",
            "a reorged transaction cannot establish finalized bundle provenance",
            current_input([
                receipt(state="included", native_order=19),
                receipt(state="reorged", timestamp=None, native_order=20),
            ]),
            indeterminate,
        ),
        vector(
            "awt-reorg-then-finalized-reentry-pass", "pass",
            "CORE-valid re-inclusion and finalization restore bundle provenance",
            current_input([
                receipt(state="included", native_order=18),
                receipt(state="reorged", timestamp=None, native_order=19),
                receipt(state="included", native_order=20, block_id="block-20b"),
                receipt(native_order=21, block_id="block-21"),
            ]),
            verified,
        ),
        vector(
            "awt-finalized-then-reorg-conflict", "indeterminate",
            "verified reorg after terminal finality is an illegal transition",
            current_input([
                receipt(native_order=20),
                receipt(state="reorged", timestamp=None, native_order=21),
            ]),
            indeterminate,
        ),
        vector(
            "awt-duplicate-finalized-snapshots-collapse", "pass",
            "byte-identical finalized snapshots collapse without changing provenance",
            current_input([receipt(), receipt()]), verified,
        ),
        vector(
            "awt-unorderable-same-native-order-indeterminate", "indeterminate",
            "different lifecycle snapshots at one native order are unorderable",
            current_input([
                receipt(state="accepted", timestamp=None, native_order=20),
                receipt(state="included", native_order=20),
            ]),
            indeterminate,
        ),
    ]

    vectors += [
        vector(
            "awt-missing-outcome-evidence-indeterminate", "indeterminate",
            "unavailable occurrence evidence is non-countable without an audit-clock fallback",
            current_input(outcome_evidence=[]), indeterminate,
        ),
        vector(
            "awt-evidence-valid-flag-cannot-supply-occurrence", "indeterminate",
            "a producer validity flag cannot replace verifier-policy evidence",
            current_input(outcome_evidence=[{"evidenceValid": True}]), indeterminate,
        ),
        vector(
            "awt-unsupported-outcome-policy-indeterminate", "indeterminate",
            "an untrusted verifier-selected policy cannot establish occurrence",
            current_input(outcomeTimePolicy={**TRUSTED_OUTCOME_POLICY, "policyId": "other"}),
            indeterminate,
        ),
        vector(
            "awt-unknown-outcome-proof-indeterminate", "indeterminate",
            "an adapter projection absent from verifier trust cannot establish occurrence",
            current_input(outcome_evidence=[{
                **outcome_time_evidence(), "proofRef": "fixture-outcome-unknown"
            }]),
            indeterminate,
        ),
        vector(
            "awt-conflicting-outcome-events-indeterminate", "indeterminate",
            "two trusted but contradictory occurrence events cannot be cherry-picked",
            current_input(outcome_evidence=[
                outcome_time_evidence(),
                outcome_time_evidence("fixture-outcome-2100-conflict"),
            ]),
            indeterminate,
        ),
        vector(
            "awt-duplicate-outcome-evidence-collapse", "pass",
            "byte-identical adapter projections collapse deterministically",
            current_input(outcome_evidence=[
                outcome_time_evidence(), outcome_time_evidence()
            ]),
            verified,
        ),
    ]

    object_mutations = (
        (
            "bundle-content-hash",
            lambda objects: objects["sessionOutcome"].__setitem__(
                "bundleContentHash", "88" * 32
            ),
            "the occurrence proof must bind the exact authoritative bundle",
        ),
        (
            "job-id",
            lambda objects: objects["sessionOutcome"].__setitem__(
                "jobId", "01K4AWT0000000000000000002"
            ),
            "the occurrence proof must bind the exact session",
        ),
        (
            "outcome",
            lambda objects: objects["sessionOutcome"].__setitem__(
                "outcome", "failed-counterparty"
            ),
            "the occurrence proof must bind the selected business outcome",
        ),
        (
            "pipeline-phase-kind",
            lambda objects: objects["listingPipeline"]["phases"][1].__setitem__(
                "kind", "deliver-storage-program"
            ),
            "the occurrence proof must bind the authenticated effective pipeline",
        ),
        (
            "terminal-evidence-job",
            lambda objects: objects["terminalPhaseEvidence"][1].__setitem__(
                "jobId", "01K4AWT0000000000000000002"
            ),
            "terminal evidence must join to the exact job",
        ),
        (
            "terminal-evidence-phase",
            lambda objects: objects["terminalPhaseEvidence"][1].__setitem__(
                "phaseIndex", 2
            ),
            "terminal evidence must join to the exact pipeline phase",
        ),
        (
            "terminal-evidence-kind",
            lambda objects: objects["terminalPhaseEvidence"][1].__setitem__(
                "phaseKind", "deliver-storage-program"
            ),
            "terminal evidence must join to the exact phase kind",
        ),
        (
            "payment-only-incomplete-job",
            lambda objects: objects.__setitem__(
                "terminalPhaseEvidence", objects["terminalPhaseEvidence"][:1]
            ),
            "one successful payment does not prove a multi-phase job completed",
        ),
    )
    for name, mutate, note in object_mutations:
        objects = copy.deepcopy(OUTCOME_BINDING_OBJECTS)
        mutate(objects)
        vectors.append(vector(
            f"awt-outcome-object-{name}-indeterminate", "indeterminate", note,
            current_input(outcomeBindingObjects=objects), indeterminate,
        ))

    for outcome in ("failed-counterparty", "aborted-by-other"):
        bundle = copy.deepcopy(BUNDLE)
        bundle["outcome"] = outcome
        objects = copy.deepcopy(OUTCOME_BINDING_OBJECTS)
        objects["sessionOutcome"]["outcome"] = outcome
        vectors.append(vector(
            f"awt-{outcome}-cannot-inherit-payment-or-anchor-time", "indeterminate",
            "failure or abort needs its own supported exact-outcome occurrence proof",
            current_input(bundle=bundle, outcomeBindingObjects=objects), indeterminate,
        ))

    event_mutations = (
        ("job-id", lambda event: event.__setitem__("jobId", "other-job")),
        ("outcome", lambda event: event.__setitem__("outcome", "failed-counterparty")),
        ("bundle-hash", lambda event: event.__setitem__("bundleContentHash", "99" * 32)),
        ("transaction", lambda event: event.__setitem__("transactionRef", transaction_ref("tx-other"))),
        ("event-index", lambda event: event.__setitem__("eventIndex", "9")),
        ("timestamp", lambda event: event.__setitem__("timestamp", 2_001)),
        ("native-order", lambda event: event.__setitem__("nativeOrder", 22)),
    )
    for name, mutate in event_mutations:
        evidence = outcome_time_evidence()
        mutate(evidence["nativeEvent"])
        vectors.append(vector(
            f"awt-native-event-{name}-mismatch-indeterminate", "indeterminate",
            "the trusted adapter record and exact native event projection must agree",
            current_input(outcome_evidence=[evidence]), indeterminate,
        ))

    malformed_receipts = (
        ("receipt-array", lambda item: []),
        ("transaction-ref-array", lambda item: mutate_receipt(item, lambda r: r.__setitem__("transactionRef", []))),
        ("transaction-kind-container", lambda item: mutate_receipt(item, lambda r: r["transactionRef"].__setitem__("kind", []))),
        ("block-ref-array", lambda item: mutate_receipt(item, lambda r: r.__setitem__("blockRef", []))),
        ("block-id-container", lambda item: mutate_receipt(item, lambda r: r["blockRef"].__setitem__("id", []))),
        ("timestamp-container", lambda item: mutate_receipt(item, lambda r: r["blockRef"].__setitem__("timestamp", []))),
        ("native-order-container", lambda item: mutate_receipt(item, lambda r: r.__setitem__("nativeOrder", []))),
        ("state-container", lambda item: mutate_receipt(item, lambda r: r.__setitem__("state", []))),
        ("disposition-container", lambda item: mutate_receipt(item, lambda r: r.__setitem__("observationDisposition", []))),
        ("native-evidence-array", lambda item: {**item, "evidence": []}),
    )
    for name, mutate in malformed_receipts:
        malformed = mutate(receipt())
        vectors.append(vector(
            f"awt-malformed-{name}-indeterminate", "indeterminate",
            "malformed nested anchor projections fail closed without raising",
            current_input([malformed]), indeterminate,
        ))

    for name, mutate in (
        (
            "replacement-transaction-array",
            lambda item: item.__setitem__("replacementTransactionRef", []),
        ),
        (
            "replacement-relation-array",
            lambda item: item.__setitem__("replacementRelation", []),
        ),
        (
            "replacement-predecessor-array",
            lambda item: item["replacementRelation"].__setitem__("predecessor", []),
        ),
        (
            "replacement-successor-array",
            lambda item: item["replacementRelation"].__setitem__("replacement", []),
        ),
        (
            "replacement-proof-container",
            lambda item: item["replacementRelation"].__setitem__("proofRef", []),
        ),
    ):
        malformed = mutate_receipt(replacement_receipt(), mutate)
        vectors.append(vector(
            f"awt-malformed-{name}-indeterminate", "indeterminate",
            "malformed replacement projections fail closed before authorization",
            current_input([malformed, successor]), indeterminate,
        ))

    malformed_outcome_inputs = (
        ("outcome-history-object", {"knownOutcomeTimeEvidence": {}}),
        ("outcome-evidence-array", {"knownOutcomeTimeEvidence": [[]]}),
        ("outcome-policy-array", {"outcomeTimePolicy": []}),
        ("outcome-objects-array", {"outcomeBindingObjects": []}),
        ("session-outcome-array", {"outcomeBindingObjects": {**copy.deepcopy(OUTCOME_BINDING_OBJECTS), "sessionOutcome": []}}),
        ("pipeline-phases-object", {"outcomeBindingObjects": {**copy.deepcopy(OUTCOME_BINDING_OBJECTS), "listingPipeline": {**copy.deepcopy(PIPELINE), "phases": {}}}}),
        ("terminal-evidence-object", {"outcomeBindingObjects": {**copy.deepcopy(OUTCOME_BINDING_OBJECTS), "terminalPhaseEvidence": {}}}),
    )
    for name, changes in malformed_outcome_inputs:
        vectors.append(vector(
            f"awt-malformed-{name}-indeterminate", "indeterminate",
            "malformed outcome-binding input is unavailable, never a recent result",
            current_input(**changes), indeterminate,
        ))

    for name, mutate in (
        ("native-event-array", lambda evidence: evidence.__setitem__("nativeEvent", [])),
        ("object-hashes-array", lambda evidence: evidence.__setitem__("objectHashes", [])),
        ("native-transaction-array", lambda evidence: evidence["nativeEvent"].__setitem__("transactionRef", [])),
        ("native-timestamp-string", lambda evidence: evidence["nativeEvent"].__setitem__("timestamp", "2000")),
        ("native-order-container", lambda evidence: evidence["nativeEvent"].__setitem__("nativeOrder", [])),
        ("proof-ref-container", lambda evidence: evidence.__setitem__("proofRef", [])),
    ):
        evidence = outcome_time_evidence()
        mutate(evidence)
        vectors.append(vector(
            f"awt-malformed-outcome-{name}-indeterminate", "indeterminate",
            "malformed nested outcome-time evidence fails closed without raising",
            current_input(outcome_evidence=[evidence]), indeterminate,
        ))

    vectors += [
        vector(
            "awt-wrong-current-window-basis", "error",
            "the current discriminator accepts only the business-occurrence basis",
            current_input(windowingBasis="sr2-finalized-inclusion-timestamp"),
            indeterminate,
        ),
        vector(
            "awt-current-plus-legacy-discriminator", "error",
            "multiple derivation discriminators are rejected before metrics are used",
            current_input(derivationDiscriminators={
                "authenticatedWindowDerivationVersion": "1",
                "derivationVersion": "1",
            }),
            indeterminate,
        ),
        vector(
            "awt-missing-current-discriminator", "error",
            "a derivation with no discriminator cannot claim current semantics",
            current_input(derivationDiscriminators={}), indeterminate,
        ),
        vector(
            "awt-wrong-current-discriminator-version", "fail",
            "an unsupported current version is not reinterpreted as version 1",
            current_input(derivationDiscriminators={
                "authenticatedWindowDerivationVersion": "2"
            }),
            want(countable=False, member=False, timestamp=None, current=False),
        ),
        vector(
            "awt-unknown-derivation-discriminator", "fail",
            "an unknown derivation is rejected rather than downgraded",
            current_input(derivationDiscriminators={"futureDerivationVersion": "1"}),
            want(countable=False, member=False, timestamp=None, current=False),
        ),
    ]

    replay_receipts = [replaced, successor]
    replay_outcome = [
        outcome_time_evidence(),
        outcome_time_evidence("fixture-outcome-2000-secondary"),
    ]
    valid_replay = replay_input(replay_receipts, replay_outcome)
    vectors.append(vector(
        "awt-replay-concrete-gate-pass", "pass",
        "replay re-verifies exact anchor lifecycle and outcome occurrence histories",
        valid_replay, verified,
    ))

    for key, slug in (
        ("outcomeTimePolicy", "missing-outcome-policy"),
        ("anchorReceipt", "missing-anchor-receipt"),
        ("anchorReceiptHistory", "missing-anchor-history"),
        ("outcomeTimeEvidence", "missing-outcome-evidence"),
        ("outcomeTimeEvidenceHistory", "missing-outcome-history"),
    ):
        changed = copy.deepcopy(valid_replay)
        changed["replayContext"].pop(key)
        vectors.append(vector(
            f"awt-replay-{slug}", "fail",
            "replay refuses omission of a dependency used by the shared gate",
            changed, indeterminate,
        ))

    replay_mutations = (
        (
            "substituted-outcome-policy",
            lambda context: context.__setitem__("outcomeTimePolicy", "other-policy"),
        ),
        (
            "non-string-outcome-policy",
            lambda context: context.__setitem__("outcomeTimePolicy", {}),
        ),
        (
            "substituted-anchor-transaction",
            lambda context: context["anchorReceipt"].__setitem__(
                "transactionRef", transaction_ref("tx-other")
            ),
        ),
        (
            "substituted-anchor-proof",
            lambda context: context["anchorReceipt"]["evidence"].__setitem__(
                "value", "other-proof"
            ),
        ),
        (
            "misordered-anchor-history",
            lambda context: context["anchorReceiptHistory"].reverse(),
        ),
        (
            "substituted-outcome-timestamp",
            lambda context: context["outcomeTimeEvidence"]["nativeEvent"].__setitem__(
                "timestamp", 2_001
            ),
        ),
        (
            "substituted-outcome-transaction",
            lambda context: context["outcomeTimeEvidence"]["nativeEvent"].__setitem__(
                "transactionRef", transaction_ref("tx-other")
            ),
        ),
        (
            "substituted-outcome-proof",
            lambda context: context["outcomeTimeEvidence"].__setitem__(
                "proofRef", "fixture-outcome-unknown"
            ),
        ),
        (
            "misordered-outcome-history",
            lambda context: context["outcomeTimeEvidenceHistory"].reverse(),
        ),
        (
            "different-passing-outcome-proof",
            lambda context: context.__setitem__(
                "outcomeTimeEvidence", outcome_time_evidence("fixture-outcome-1000")
            ),
        ),
    )
    for name, mutate in replay_mutations:
        changed = copy.deepcopy(valid_replay)
        mutate(changed["replayContext"])
        vectors.append(vector(
            f"awt-replay-{name}", "fail",
            "replay refuses changed evidence and never substitutes another passing clock",
            changed, indeterminate,
        ))

    rejected_legacy = want(
        countable=False, member=False, timestamp=None, current=False
    )
    eligible_legacy = want(
        countable=False, member=False, timestamp=None,
        current=False, historical=True,
    )
    vectors.append(vector(
        "awt-legacy-producer-time-is-not-era-evidence", "fail",
        "producer clocks and assertions cannot authenticate a historical era",
        {
            **historical_input("replayableDerivationVersion", verified=False),
            "historicalPolicy": True,
            "eraEvidence": {"kind": "producer-assertion", "computedAt": 1},
        },
        rejected_legacy,
    ))

    slugs = {
        "derivationVersion": "derivation",
        "replayableDerivationVersion": "replayable-derivation",
        "jobBoundReplayableDerivationVersion": "job-bound-replayable-derivation",
        "settlementVerifiedDerivationVersion": "settlement-verified-derivation",
        "replayableSettlementVerifiedDerivationVersion": (
            "replayable-settlement-verified-derivation"
        ),
    }
    for discriminator in LEGACY_DISCRIMINATORS:
        slug = slugs[discriminator]
        vectors.append(vector(
            f"awt-{slug}-cannot-claim-current", "fail",
            f"{discriminator} cannot satisfy a current-profile request",
            historical_input(discriminator, verified=False), rejected_legacy,
        ))
        vectors.append(vector(
            f"awt-{slug}-exact-era-is-historical-only", "pass",
            "trusted era evidence binds the JCS hash of this exact unsigned derivation",
            historical_input(discriminator, verified=True), eligible_legacy,
        ))

        historical_mutations = (
            (
                "discriminator",
                lambda derivation, d=discriminator: derivation.__setitem__(d, "2"),
            ),
            (
                "party",
                lambda derivation: derivation["partyPrimaryClaim"].__setitem__(
                    "identifier", "demos1attacker"
                ),
            ),
            (
                "window-start",
                lambda derivation: derivation.__setitem__("windowStart", 999),
            ),
            (
                "window-end",
                lambda derivation: derivation.__setitem__("windowEnd", 3_001),
            ),
            (
                "bundle-refs",
                lambda derivation: derivation["bundleRefs"][0].__setitem__(
                    "contentHash", "aa" * 32
                ),
            ),
            (
                "metrics",
                lambda derivation: derivation["metrics"].__setitem__(
                    "completionRate", 0
                ),
            ),
        )
        for field, mutate in historical_mutations:
            changed = historical_input(discriminator, verified=True)
            mutate(changed["historicalDerivation"])
            vectors.append(vector(
                f"awt-{slug}-era-{field}-mutation-rejected", "fail",
                "era eligibility is bound to the exact derivation object, not a projection",
                changed, rejected_legacy,
            ))
        if discriminator in REPLAYABLE_LEGACY_DISCRIMINATORS:
            changed = historical_input(discriminator, verified=True)
            changed["historicalDerivation"]["resolutionContext"][0][
                "resolvedRole"
            ] = "seller"
            vectors.append(vector(
                f"awt-{slug}-era-resolution-context-mutation-rejected", "fail",
                "era evidence binds the exact replay context where the type carries it",
                changed, rejected_legacy,
            ))

    for field, value in (
        ("verificationDisposition", "unverified"),
        ("producer", "did:demos:other-producer"),
        ("sessionId", "01K4AWT0000000000000000002"),
        ("profile", "dacs-next-dacs-5-v0.4"),
        ("commit", "0" * 40),
        ("revisionRelation", "same-as-current"),
        ("derivationHash", "0" * 64),
    ):
        changed = historical_input("replayableDerivationVersion", verified=True)
        changed["eraEvidence"][field] = value
        vectors.append(vector(
            f"awt-era-{field.lower()}-mismatch-rejected", "fail",
            "the fixture trust record and exact era projection must agree",
            changed, rejected_legacy,
        ))

    changed = historical_input("replayableDerivationVersion", verified=True)
    changed["trustedEraPolicy"]["policyId"] = "attacker-policy"
    changed["eraEvidence"]["policyId"] = "attacker-policy"
    vectors.append(vector(
        "awt-era-coordinated-policy-and-evidence-tampering-rejected", "fail",
        "caller-coordinated policy changes cannot replace verifier trust configuration",
        changed, rejected_legacy,
    ))
    return vectors


def document() -> dict:
    vectors = build_vectors()
    encoded = json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()
    return {
        "set": SET_NAME,
        "spec": SPEC,
        "decisionModel": (
            "pass may count an in-window job or exclude an out-of-window job; "
            "indeterminate is always non-countable; error/fail cannot satisfy current use"
        ),
        "inputModel": (
            "one authoritative copy after external two-copy reconciliation and RSV; the "
            "fixture-only harness executes resolve_current/replay countability and membership using an "
            "exact-object binding-adapter projection trusted separately by the verifier. "
            "It models, but does not verify, native proof bytes or a production adapter"
        ),
        "anchorModel": (
            "Anchor receipts retain exact-bundle provenance/finality and CORE lifecycle "
            "semantics only; their timestamps, observedAt, evidenceValid, finalisedAt and "
            "SessionRecord.endedAt never supply business occurrence authority"
        ),
        "outcomeHistoryModel": (
            "The fixture-only dacs-test-outcome-binding-v1 policy collapses byte-identical "
            "evidence, orders by nativeEvent.nativeOrder ascending, and breaks ties by "
            "lower-case sha256(RFC 8785 JCS(exact evidence object)) ascending. This "
            "serialization tie-break supplies no occurrence or causal authority."
        ),
        "hash": hashlib.sha256(encoded).hexdigest(),
        "count": len(vectors),
        "vectors": vectors,
    }


def render_document(data: dict) -> str:
    """Keep each vector on one reviewable line, matching the existing corpora."""
    lines = ["{"]
    metadata = [(key, value) for key, value in data.items() if key != "vectors"]
    for key, value in metadata:
        lines.append(
            f"  {json.dumps(key)}: {json.dumps(value, ensure_ascii=False)},"
        )
    lines.append('  "vectors": [')
    vectors = data["vectors"]
    for index, item in enumerate(vectors):
        comma = "," if index + 1 < len(vectors) else ""
        lines.append(
            "    "
            + json.dumps(item, separators=(", ", ": "), ensure_ascii=False)
            + comma
        )
    lines.extend(["  ]", "}"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = render_document(document())
    if args.write:
        OUTPUT.write_text(rendered, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
        print(f"ERROR: {OUTPUT.relative_to(ROOT)} is stale; run this script with --write")
        return 1
    print(f"authenticated-window vectors OK ({len(build_vectors())} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
