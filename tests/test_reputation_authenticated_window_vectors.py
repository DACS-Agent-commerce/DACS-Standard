import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.jcs import canonicalize as jcs_canonicalize


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "reputation-authenticated-window-v0.6.json"
)
GENERATOR = ROOT / "scripts" / "generate_reputation_authenticated_window_vectors.py"
SPEC = ROOT / "spec" / "DACS-5-VERIFY.md"

JOB_ID = "01K4AWT0000000000000000001"
CURRENT = {"authenticatedWindowDerivationVersion": "1"}
LEGACY_DISCRIMINATORS = {
    "derivationVersion",
    "replayableDerivationVersion",
    "jobBoundReplayableDerivationVersion",
    "settlementVerifiedDerivationVersion",
    "replayableSettlementVerifiedDerivationVersion",
}
REPLAYABLE_LEGACY_DISCRIMINATORS = {
    "replayableDerivationVersion",
    "jobBoundReplayableDerivationVersion",
    "replayableSettlementVerifiedDerivationVersion",
}
BINDING_FIELDS = (
    "substrate", "logicalAddress", "nativeAddress", "contentHash", "writer", "nonce",
)
MAX_SAFE_INTEGER = 2**53 - 1
TRUSTED_ERA_POLICY = {
    "policyId": "dacs-test-era-policy-v1",
    "adapter": "conformance-harness-profile-era-v1",
    "authority": "did:demos:steward",
    "producer": "did:demos:legacy-reputation-producer",
    "sessionId": JOB_ID,
    "profile": "dacs-next-dacs-5-v0.5",
    "commit": "3426faaebc09948d57a3a6d30fd6795df579b68f",
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
    "transactionRef": {"kind": "demos-tx", "value": "tx-window-a"},
    "jobId": JOB_ID,
    "outcome": "completed",
}
SELLER_LOGICAL_ADDRESS = "stor-" + "33" * 32
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
OUTCOME_FIXTURES = {
    "fixture-outcome-0999": (999, 9, "tx-job-complete-0999", "0"),
    "fixture-outcome-1000": (1_000, 10, "tx-job-complete-1000", "0"),
    "fixture-outcome-2000": (2_000, 20, "tx-job-complete-2000", "0"),
    "fixture-outcome-2000-secondary": (
        2_000, 20, "tx-job-complete-2000", "0"
    ),
    "fixture-outcome-2100-conflict": (
        2_100, 21, "tx-job-complete-conflict", "1"
    ),
    "fixture-outcome-3000": (3_000, 30, "tx-job-complete-3000", "0"),
    "fixture-outcome-3001": (3_001, 31, "tx-job-complete-3001", "0"),
}
CURRENT_INPUT_FIELDS = {
    "derivationDiscriminators", "windowingBasis", "windowStart", "windowEnd",
    "bundleFinalisedAt", "sessionRecordEndedAt", "bundle", "knownReceipts",
    "outcomeTimePolicy", "outcomeBindingObjects", "knownOutcomeTimeEvidence",
    "replayContext", "historicalPolicy", "trustedEraPolicy", "eraEvidence",
}

CORE_TRANSITIONS = {
    "submitted": {"accepted", "rejected"},
    "accepted": {"included", "dropped", "replaced", "expired"},
    "included": {"finalized", "reorged"},
    "dropped": {"accepted", "included", "replaced"},
    "expired": {"accepted", "included", "replaced"},
    "reorged": {"accepted", "included", "replaced"},
    "finalized": set(),
    "rejected": set(),
    "replaced": set(),
}

# CORE §5.1 permits a deterministic-BFT binding to declare that valid inclusion
# is final, collapsing one authenticated observation into both `included` and
# `finalized`. DEMOS-MAPPING §A.2 declares inclusion-final semantics under the
# single `demos-bft-final` profile, so that profile authorizes the compressed
# submitted/accepted → finalized edges without weakening any other non-final,
# late, or replacement check. Any other profile is undeclared and rejected, and
# a history that switches profiles is a cross-profile/mixed-history attempt and
# is likewise rejected.
FINALITY_PROFILE_STANDARD = "demos-bft-final"
FINALITY_PROFILES = {FINALITY_PROFILE_STANDARD}
COMPRESSED_FINALITY_PREDECESSORS = {"submitted", "accepted"}


def jcs_hash(value):
    return hashlib.sha256(jcs_canonicalize(value).encode("utf-8")).hexdigest()


def vector_hash(vectors):
    encoded = json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def indeterminate_want(*, current=True):
    return {
        "currentProfile": current,
        "historicalEligible": False,
        "timeDisposition": "indeterminate",
        "countable": False,
        "windowMember": False,
        "windowTimestamp": None,
        "clockSource": None,
    }


def safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_SAFE_INTEGER
    )


def nonempty_string(value):
    return isinstance(value, str) and bool(value)


def valid_decimal_string(value):
    return (
        isinstance(value, str)
        and bool(value)
        and all(ch in "0123456789" for ch in value)
        and (value == "0" or value[0] != "0")
    )


def valid_transaction_ref(value):
    return (
        isinstance(value, dict)
        and set(value) == {"kind", "value"}
        and nonempty_string(value.get("kind"))
        and nonempty_string(value.get("value"))
    )


def transaction_key(value):
    return (value["kind"], value["value"])


def receipt_projection_hash(item):
    try:
        scope = {key: value for key, value in item.items() if key != "evidence"}
        return jcs_hash(scope)
    except (AttributeError, TypeError, ValueError):
        return None


def receipt_is_authenticated(item):
    if not isinstance(item, dict):
        return False
    evidence = item.get("evidence")
    return (
        isinstance(evidence, dict)
        and set(evidence) == {"kind", "value"}
        and evidence.get("kind")
        == "fixture-only-anchor-binding-adapter-projection"
        and nonempty_string(evidence.get("value"))
        and evidence["value"] == receipt_projection_hash(item)
    )


def receipt_binds_bundle(item, bundle):
    return all(item.get(field) == bundle.get(field) for field in BINDING_FIELDS)


def valid_block_ref(value):
    if not isinstance(value, dict) or not set(value) <= {
        "id", "height", "timestamp"
    }:
        return False
    if "id" not in value:
        return False
    if not nonempty_string(value.get("id")):
        return False
    if "height" in value and not valid_decimal_string(value.get("height")):
        return False
    if "timestamp" in value and not safe_integer(value["timestamp"]):
        return False
    return True


def valid_replacement_relation(value, item):
    return (
        isinstance(value, dict)
        and set(value) == {
            "kind", "predecessor", "replacement", "proofRef"
        }
        and value.get("kind")
        == "fixture-only-authenticated-replacement-projection"
        and valid_transaction_ref(value.get("predecessor"))
        and valid_transaction_ref(value.get("replacement"))
        and nonempty_string(value.get("proofRef"))
        and value["predecessor"] == item.get("transactionRef")
        and value["replacement"] == item.get("replacementTransactionRef")
    )


def receipt_is_well_formed(item):
    if not isinstance(item, dict):
        return False
    state = item.get("state")
    disposition = item.get("observationDisposition")
    if not isinstance(state, str) or state not in CORE_TRANSITIONS:
        return False
    if not isinstance(disposition, str) or disposition not in {
        "established", "indeterminate"
    }:
        return False
    required = {
        "receiptVersion", *BINDING_FIELDS, "finalityProfile", "transactionRef",
        "state", "observationDisposition", "observedAt", "nativeOrder", "evidence",
    }
    if state in {"included", "finalized"}:
        required.add("blockRef")
    if state == "replaced":
        required.update({"replacementTransactionRef", "replacementRelation"})
    if disposition == "indeterminate":
        required.add("preservedReceiptHash")
    if set(item) != required:
        return False
    if item.get("receiptVersion") != "1":
        return False
    if item.get("finalityProfile") not in FINALITY_PROFILES:
        return False
    if any(not nonempty_string(item.get(field)) for field in BINDING_FIELDS):
        return False
    if not valid_transaction_ref(item.get("transactionRef")):
        return False
    if not safe_integer(item.get("observedAt")) or not safe_integer(item.get("nativeOrder")):
        return False
    if state in {"included", "finalized"} and not valid_block_ref(item.get("blockRef")):
        return False
    if disposition == "indeterminate" and not (
        isinstance(item.get("preservedReceiptHash"), str)
        and len(item["preservedReceiptHash"]) == 64
    ):
        return False
    if state == "replaced" and not (
        disposition == "established"
        and valid_transaction_ref(item.get("replacementTransactionRef"))
        and valid_replacement_relation(item.get("replacementRelation"), item)
    ):
        return False
    return True


def receipt_hash(value):
    return jcs_hash(value)


def canonical_receipt_history(items):
    unique = {receipt_hash(item): item for item in items}
    return [
        copy.deepcopy(item)
        for digest, item in sorted(
            unique.items(), key=lambda pair: (pair[1]["nativeOrder"], pair[0])
        )
    ]


def relation_proof_ref(predecessor, replacement, native_order):
    return "fixture-only-replacement:" + jcs_hash({
        "predecessor": predecessor,
        "replacement": replacement,
        "nativeOrder": native_order,
    })


def replacement_relation_is_verified(item):
    relation = item["replacementRelation"]
    return relation["proofRef"] == relation_proof_ref(
        relation["predecessor"], relation["replacement"], item["nativeOrder"]
    )


def replacement_graph_has_cycle(edges):
    visiting = set()
    visited = set()

    def walk(node):
        if node in visiting:
            return True
        if node in visited or node not in edges:
            return False
        visiting.add(node)
        if walk(edges[node][0]):
            return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(walk(node) for node in edges)


def resolve_anchor_history(bundle, receipts):
    if not isinstance(bundle, dict) or not isinstance(receipts, list):
        return "error", None, []
    if not valid_transaction_ref(bundle.get("transactionRef")):
        return "error", None, []

    authenticated = [
        item for item in receipts
        if receipt_is_authenticated(item) and receipt_binds_bundle(item, bundle)
    ]
    if any(not receipt_is_well_formed(item) for item in authenticated):
        return "indeterminate", None, []
    history = canonical_receipt_history(authenticated)
    if not history:
        return "indeterminate", None, history

    positions = {}
    for item in history:
        key = (transaction_key(item["transactionRef"]), item["nativeOrder"])
        positions.setdefault(key, set()).add(receipt_hash(item))
    if any(len(digests) > 1 for digests in positions.values()):
        return "indeterminate", None, history

    by_transaction = {}
    for item in history:
        by_transaction.setdefault(transaction_key(item["transactionRef"]), []).append(item)

    last_established = {}
    established_by_transaction = {}
    for key, snapshots in by_transaction.items():
        last = None
        established = []
        for item in snapshots:
            if item["observationDisposition"] == "indeterminate":
                if not (
                    last is not None
                    and item["state"] == last["state"]
                    and item["preservedReceiptHash"] == receipt_hash(last)
                ):
                    return "indeterminate", None, history
                continue
            if last is not None:
                if item["nativeOrder"] <= last["nativeOrder"]:
                    return "indeterminate", None, history
                if item["state"] not in CORE_TRANSITIONS[last["state"]]:
                    compressed_finality = (
                        item["state"] == "finalized"
                        and last["state"] in COMPRESSED_FINALITY_PREDECESSORS
                        and item.get("finalityProfile")
                        == FINALITY_PROFILE_STANDARD
                    )
                    if not compressed_finality:
                        return "indeterminate", None, history
            last = item
            established.append(item)
        if last is not None:
            last_established[key] = last
            established_by_transaction[key] = established

    edges_by_predecessor = {}
    for key, snapshots in established_by_transaction.items():
        states = {item["state"] for item in snapshots}
        if "finalized" in states and "replaced" in states:
            return "indeterminate", None, history
        for item in snapshots:
            if item["state"] != "replaced" or not replacement_relation_is_verified(item):
                continue
            successor = transaction_key(item["replacementTransactionRef"])
            edges_by_predecessor.setdefault(key, []).append(
                (successor, item["nativeOrder"])
            )

    if any(
        len({successor for successor, _ in edges}) > 1
        for edges in edges_by_predecessor.values()
    ):
        return "indeterminate", None, history
    edges = {
        predecessor: values[0]
        for predecessor, values in edges_by_predecessor.items()
    }
    if replacement_graph_has_cycle(edges):
        return "indeterminate", None, history

    for predecessor, (successor, edge_order) in edges.items():
        successor_snapshots = established_by_transaction.get(successor, [])
        successor_final = [
            item for item in successor_snapshots if item["state"] == "finalized"
        ]
        successor_replacement = [
            item for item in successor_snapshots if item["state"] == "replaced"
        ]
        if any(
            item["nativeOrder"] <= edge_order
            for item in successor_final + successor_replacement
        ):
            return "indeterminate", None, history

    expected = transaction_key(bundle["transactionRef"])
    authorized = {expected}
    cursor = expected
    while cursor in edges:
        cursor = edges[cursor][0]
        authorized.add(cursor)

    finalized = [
        item for key, item in last_established.items()
        if key in authorized and item["state"] == "finalized"
    ]
    if len(finalized) != 1:
        return "indeterminate", None, history
    return "pass", copy.deepcopy(finalized[0]), history


def outcome_object_hashes(objects):
    try:
        return {
            "sessionOutcome": jcs_hash(objects["sessionOutcome"]),
            "listingPipeline": jcs_hash(objects["listingPipeline"]),
            "terminalPhaseEvidence": jcs_hash(objects["terminalPhaseEvidence"]),
        }
    except (KeyError, TypeError, ValueError):
        return None


def trusted_outcome_evidence(proof_ref):
    if proof_ref not in OUTCOME_FIXTURES:
        return None
    timestamp, native_order, transaction, event_index = OUTCOME_FIXTURES[proof_ref]
    return {
        "projectionVersion": "1",
        "kind": "fixture-only-binding-adapter-outcome-time",
        "policyId": TRUSTED_OUTCOME_POLICY["policyId"],
        "proofRef": proof_ref,
        "objectHashes": outcome_object_hashes(OUTCOME_BINDING_OBJECTS),
        "nativeEvent": {
            "kind": "fixture-only-job-outcome-event",
            "transactionRef": {"kind": "demos-tx", "value": transaction},
            "eventIndex": event_index,
            "nativeOrder": native_order,
            "timestamp": timestamp,
            "jobId": JOB_ID,
            "outcome": "completed",
            "bundleContentHash": BUNDLE["contentHash"],
        },
    }


def valid_attestation_ref(value):
    return (
        isinstance(value, dict)
        and set(value) == {"anchor", "contentHash"}
        and isinstance(value.get("anchor"), dict)
        and set(value["anchor"]) == {"kind", "locator"}
        and nonempty_string(value["anchor"].get("kind"))
        and nonempty_string(value["anchor"].get("locator"))
        and nonempty_string(value.get("contentHash"))
    )


def outcome_objects_join(bundle, objects):
    if not isinstance(objects, dict) or set(objects) != {
        "sessionOutcome", "listingPipeline", "terminalPhaseEvidence"
    }:
        return False
    session = objects.get("sessionOutcome")
    pipeline = objects.get("listingPipeline")
    terminal = objects.get("terminalPhaseEvidence")
    if not (
        isinstance(session, dict)
        and set(session) == {"jobId", "bundleContentHash", "outcome"}
        and session.get("jobId") == bundle.get("jobId")
        and session.get("bundleContentHash") == bundle.get("contentHash")
        and session.get("outcome") == bundle.get("outcome")
    ):
        return False
    if not (
        isinstance(pipeline, dict)
        and set(pipeline) == {"listingId", "listingVersion", "phases"}
        and nonempty_string(pipeline.get("listingId"))
        and nonempty_string(pipeline.get("listingVersion"))
        and isinstance(pipeline.get("phases"), list)
        and pipeline["phases"]
    ):
        return False
    phase_keys = []
    for phase in pipeline["phases"]:
        if not (
            isinstance(phase, dict)
            and set(phase) == {"phaseIndex", "kind"}
            and safe_integer(phase.get("phaseIndex"))
            and nonempty_string(phase.get("kind"))
        ):
            return False
        phase_keys.append((phase["phaseIndex"], phase["kind"]))
    if len(phase_keys) != len(set(phase_keys)):
        return False
    if not isinstance(terminal, list) or not terminal:
        return False
    terminal_keys = []
    for evidence in terminal:
        if not (
            isinstance(evidence, dict)
            and set(evidence) == {
                "jobId", "phaseIndex", "phaseKind", "evidenceRef"
            }
            and evidence.get("jobId") == session["jobId"]
            and safe_integer(evidence.get("phaseIndex"))
            and nonempty_string(evidence.get("phaseKind"))
            and valid_attestation_ref(evidence.get("evidenceRef"))
        ):
            return False
        terminal_keys.append((evidence["phaseIndex"], evidence["phaseKind"]))
    return sorted(terminal_keys) == sorted(phase_keys)


def outcome_evidence_is_verified(item):
    if not isinstance(item, dict) or not isinstance(item.get("proofRef"), str):
        return False
    expected = trusted_outcome_evidence(item["proofRef"])
    return expected is not None and item == expected


def canonical_outcome_history(items):
    unique = {jcs_hash(item): item for item in items}
    return [
        copy.deepcopy(item)
        for digest, item in sorted(
            unique.items(),
            key=lambda pair: (pair[1]["nativeEvent"]["nativeOrder"], pair[0]),
        )
    ]


def resolve_outcome_time(data, bundle, evidence_items):
    if data.get("outcomeTimePolicy") != TRUSTED_OUTCOME_POLICY:
        return "indeterminate", None, []
    objects = data.get("outcomeBindingObjects")
    if not outcome_objects_join(bundle, objects) or not isinstance(evidence_items, list):
        return "indeterminate", None, []
    verified = [item for item in evidence_items if outcome_evidence_is_verified(item)]
    if not verified:
        return "indeterminate", None, []
    hashes = outcome_object_hashes(objects)
    if hashes is None or any(item["objectHashes"] != hashes for item in verified):
        return "indeterminate", None, []
    history = canonical_outcome_history(verified)
    event_keys = {
        (
            event["jobId"], event["outcome"], event["bundleContentHash"],
            *transaction_key(event["transactionRef"]), event["eventIndex"],
            event["nativeOrder"], event["timestamp"],
        )
        for event in (item["nativeEvent"] for item in history)
    }
    if len(event_keys) != 1:
        return "indeterminate", None, history
    selected = history[0]
    timestamp = selected["nativeEvent"]["timestamp"]
    if not safe_integer(timestamp):
        return "indeterminate", None, history
    return "pass", copy.deepcopy(selected), history


def resolve_current(data, receipts, outcome_evidence):
    bundle = data.get("bundle")
    if not isinstance(bundle, dict):
        return "error", indeterminate_want(), None, [], None, []
    if not (
        valid_transaction_ref(bundle.get("transactionRef"))
        and nonempty_string(bundle.get("jobId"))
        and nonempty_string(bundle.get("outcome"))
    ):
        return "error", indeterminate_want(), None, [], None, []
    if not safe_integer(data.get("windowStart")) or not safe_integer(data.get("windowEnd")):
        return "error", indeterminate_want(), None, [], None, []
    if data["windowStart"] > data["windowEnd"]:
        return "error", indeterminate_want(), None, [], None, []

    anchor_status, anchor, anchor_history = resolve_anchor_history(bundle, receipts)
    if anchor_status != "pass":
        return anchor_status, indeterminate_want(), None, anchor_history, None, []
    outcome_status, outcome, outcome_history = resolve_outcome_time(
        data, bundle, outcome_evidence
    )
    if outcome_status != "pass":
        return (
            outcome_status, indeterminate_want(), anchor, anchor_history,
            None, outcome_history,
        )
    timestamp = outcome["nativeEvent"]["timestamp"]
    member = data["windowStart"] <= timestamp <= data["windowEnd"]
    return (
        "pass",
        {
            "currentProfile": True,
            "historicalEligible": False,
            "timeDisposition": "verified",
            "countable": True,
            "windowMember": member,
            "windowTimestamp": timestamp,
            "clockSource": "outcomeTimeEvidence.nativeEvent.timestamp",
        },
        anchor,
        anchor_history,
        outcome,
        outcome_history,
    )


def attestation_ref(content_hash=BUNDLE["contentHash"]):
    return {
        "anchor": {"kind": "demos-storage", "locator": "bundle-a"},
        "contentHash": content_hash,
    }


def historical_resolution_context(discriminator):
    entry = {
        "contentHash": BUNDLE["contentHash"],
        "resolvedRole": "buyer",
        "roleEvidence": {
            "kind": "address", "resolvedAddress": BUNDLE["logicalAddress"]
        },
        "counterpartyDisposition": "present",
        "counterpartyRef": attestation_ref(),
        "counterpartyRoleEvidence": {
            "kind": "address", "resolvedAddress": SELLER_LOGICAL_ADDRESS
        },
    }
    if discriminator in {
        "jobBoundReplayableDerivationVersion",
        "replayableSettlementVerifiedDerivationVersion",
    }:
        entry["resolvedJobId"] = JOB_ID
    return [entry]


def historical_derivation(discriminator):
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


def trusted_era_evidence(discriminator):
    return {
        "kind": "verified-profile-era-projection",
        "verificationDisposition": "verified",
        **copy.deepcopy(TRUSTED_ERA_POLICY),
        "derivationHash": jcs_hash(historical_derivation(discriminator)),
    }


def verified_historical_era(data, discriminator):
    policy = data.get("trustedEraPolicy")
    evidence = data.get("eraEvidence")
    derivation = data.get("historicalDerivation")
    if not isinstance(derivation, dict):
        return False
    if policy != TRUSTED_ERA_POLICY:
        return False
    if evidence != trusted_era_evidence(discriminator):
        return False
    try:
        return jcs_hash(derivation) == evidence["derivationHash"]
    except (TypeError, ValueError):
        return False


def evaluate(vector):
    data = vector["input"]
    if not isinstance(data, dict):
        return {"expected": "error", "want": indeterminate_want()}
    discriminators = data.get("derivationDiscriminators")
    if not isinstance(discriminators, dict) or len(discriminators) != 1:
        return {"expected": "error", "want": indeterminate_want()}

    if discriminators != CURRENT:
        name, version = next(iter(discriminators.items()))
        historical = (
            name in LEGACY_DISCRIMINATORS
            and version == "1"
            and data.get("historicalPolicy") is True
            and verified_historical_era(data, name)
        )
        result = indeterminate_want(current=False)
        result["historicalEligible"] = historical
        return {"expected": "pass" if historical else "fail", "want": result}

    if data.get("windowingBasis") != "verified-business-outcome-occurrence":
        return {"expected": "error", "want": indeterminate_want()}
    if set(data) != CURRENT_INPUT_FIELDS:
        return {"expected": "error", "want": indeterminate_want()}

    resolved = resolve_current(
        data, data.get("knownReceipts"), data.get("knownOutcomeTimeEvidence")
    )
    expected, wanted, anchor, anchor_history, outcome, outcome_history = resolved
    replay = data.get("replayContext")
    if replay is not None:
        if expected != "pass":
            return {"expected": "fail", "want": indeterminate_want()}
        if not isinstance(replay, dict) or set(replay) != {
            "anchorReceipt", "anchorReceiptHistory",
            "outcomeTimePolicy", "outcomeTimeEvidence", "outcomeTimeEvidenceHistory",
        }:
            return {"expected": "fail", "want": indeterminate_want()}
        if replay["outcomeTimePolicy"] != TRUSTED_OUTCOME_POLICY["policyId"]:
            return {"expected": "fail", "want": indeterminate_want()}
        replay_resolved = resolve_current(
            data,
            replay.get("anchorReceiptHistory"),
            replay.get("outcomeTimeEvidenceHistory"),
        )
        (
            replay_expected, replay_want, replay_anchor, replay_anchor_history,
            replay_outcome, replay_outcome_history,
        ) = replay_resolved
        if not (
            replay_expected == "pass"
            and replay_want == wanted
            and replay.get("anchorReceipt") == anchor == replay_anchor
            and replay.get("anchorReceiptHistory")
            == anchor_history == replay_anchor_history
            and replay.get("outcomeTimeEvidence") == outcome == replay_outcome
            and replay.get("outcomeTimeEvidenceHistory")
            == outcome_history == replay_outcome_history
        ):
            return {"expected": "fail", "want": indeterminate_want()}
    return {"expected": expected, "want": wanted}


class AuthenticatedWindowVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_vector_metadata(self):
        vectors = self.document["vectors"]
        self.assertEqual(self.document["count"], len(vectors))
        self.assertEqual(self.document["hash"], vector_hash(vectors))
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_review_closure_vectors_are_concrete_and_complete(self):
        vectors = {item["name"]: item for item in self.document["vectors"]}
        required = {
            "awt-delayed-anchor-does-not-refresh-old-outcome",
            "awt-buyer-copy-publication-date-is-inert",
            "awt-seller-copy-publication-date-is-inert",
            "awt-missing-outcome-evidence-indeterminate",
            "awt-conflicting-outcome-events-indeterminate",
            "awt-outcome-object-payment-only-incomplete-job-indeterminate",
            "awt-finalized-exact-replacement-pass",
            "awt-two-hop-replacement-pass",
            "awt-reversed-replacement-edge-indeterminate",
            "awt-late-replacement-edge-indeterminate",
            "awt-finalized-predecessor-then-replaced-indeterminate",
            "awt-cyclic-replacement-history-indeterminate",
            "awt-branching-replacement-history-indeterminate",
            "awt-replay-concrete-gate-pass",
            "awt-replay-different-passing-outcome-proof",
            "awt-finalized-anchor-without-height-pass",
            "awt-included-anchor-without-height-pass",
            "awt-finalized-anchor-canonical-decimal-height-pass",
            "awt-malformed-block-height-non-decimal-indeterminate",
            "awt-malformed-block-height-signed-indeterminate",
            "awt-malformed-block-height-plus-indeterminate",
            "awt-malformed-block-height-space-indeterminate",
            "awt-malformed-block-height-leading-zero-indeterminate",
            "awt-compressed-finality-submitted-to-finalized-pass",
            "awt-compressed-finality-accepted-to-finalized-pass",
            "awt-submitted-to-finalized-undeclared-profile-indeterminate",
            "awt-accepted-to-finalized-undeclared-profile-indeterminate",
            "awt-cross-profile-finality-history-indeterminate",
            "awt-compressed-finality-finalized-then-reorg-indeterminate",
        }
        self.assertLessEqual(required, set(vectors))
        self.assertNotIn("historyDisposition", json.dumps(self.document))
        self.assertIn("fixture-only", self.document["inputModel"])

        replay = vectors["awt-replay-concrete-gate-pass"]["input"]["replayContext"]
        self.assertGreater(len(replay["anchorReceiptHistory"]), 1)
        self.assertGreater(len(replay["outcomeTimeEvidenceHistory"]), 1)
        self.assertIn(replay["anchorReceipt"], replay["anchorReceiptHistory"])
        self.assertIn(replay["outcomeTimeEvidence"], replay["outcomeTimeEvidenceHistory"])
        self.assertEqual(replay["outcomeTimePolicy"], TRUSTED_OUTCOME_POLICY["policyId"])

        delayed = vectors["awt-delayed-anchor-does-not-refresh-old-outcome"]["input"]
        anchor_time = delayed["knownReceipts"][0]["blockRef"]["timestamp"]
        occurrence = delayed["knownOutcomeTimeEvidence"][0]["nativeEvent"]["timestamp"]
        self.assertLess(occurrence, delayed["windowStart"])
        self.assertLessEqual(delayed["windowStart"], anchor_time)
        self.assertLessEqual(anchor_time, delayed["windowEnd"])

        history = replay["outcomeTimeEvidenceHistory"]
        self.assertEqual(history[0]["nativeEvent"], history[1]["nativeEvent"])
        self.assertEqual([jcs_hash(item) for item in history], sorted(jcs_hash(item) for item in history))
        self.assertIn("sha256(RFC 8785 JCS", self.document["outcomeHistoryModel"])
        for slug in ("missing-outcome-policy", "substituted-outcome-policy", "non-string-outcome-policy"):
            self.assertEqual(evaluate(vectors[f"awt-replay-{slug}"])["expected"], "fail")

        slugs = {
            "derivation",
            "replayable-derivation",
            "job-bound-replayable-derivation",
            "settlement-verified-derivation",
            "replayable-settlement-verified-derivation",
        }
        for slug in slugs:
            self.assertIn(f"awt-{slug}-cannot-claim-current", vectors)
            self.assertIn(f"awt-{slug}-exact-era-is-historical-only", vectors)
            for field in (
                "discriminator", "party", "window-start", "window-end",
                "bundle-refs", "metrics",
            ):
                self.assertIn(f"awt-{slug}-era-{field}-mutation-rejected", vectors)

    def test_independent_reference_evaluator(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    evaluate(vector),
                    {"expected": vector["expected"], "want": vector["want"]},
                )

    def test_lifecycle_contradictions_reach_the_shared_consumer(self):
        vectors = {item["name"]: item for item in self.document["vectors"]}
        for name in (
            "awt-late-replacement-edge-indeterminate",
            "awt-finalized-predecessor-then-replaced-indeterminate",
            "awt-cyclic-replacement-history-indeterminate",
            "awt-branching-replacement-history-indeterminate",
        ):
            with self.subTest(vector=name):
                result = evaluate(vectors[name])
                self.assertEqual(result["expected"], "indeterminate")
                self.assertFalse(result["want"]["countable"])

    def test_generator_is_deterministic(self):
        subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            check=True,
        )

    def test_spec_pins_outcome_clock_and_legacy_boundary(self):
        text = SPEC.read_text(encoding="utf-8")
        self.assertIn("**DACS-5 v0.6**", text)
        self.assertIn('authenticatedWindowDerivationVersion: "1"', text)
        self.assertIn('windowingBasis: "verified-business-outcome-occurrence"', text)
        self.assertIn("(AWT-1)", text)
        self.assertIn("(AWT-8)", text)
        self.assertIn("both boundaries are inclusive", text)
        self.assertIn("outcomeTimeEvidenceHistory", text)
        self.assertIn(
            "sha256 of the shared RFC 8785 JCS serialization of the exact unsigned derivation object",
            text,
        )


if __name__ == "__main__":
    unittest.main()
