import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.jcs import canonicalize as jcs_canonicalize
from scripts.reputation_evidence import (
    decode_canonical_object,
    inspect_anchor_receipt,
    resolve_anchor_history as resolve_shared_anchor_history,
)


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
ANCHOR_ADAPTER_DOMAIN = "dacs-test-window-anchor-adapter:v1:"
ANCHOR_POLICY = "dacs-test-window-anchor-v1"
TRUSTED_ANCHOR_ADAPTER = (
    "key:786f8b3089d787d6a8946c841dfe728be88632597d6e5f9ae9d3a1bf2e78e0ba"
)

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
        "standaloneAWT": current,
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


# The AWT consumer delegates portable receipt authentication and lifecycle
# reconciliation to the same signed fixture adapter used by SPA.  Current
# admission may infer the unique finalized successor; replay supplies it exactly.
def resolve_anchor_history(bundle, receipts, selected=None):
    if not isinstance(bundle, dict) or not valid_transaction_ref(
        bundle.get("transactionRef")
    ):
        return "error", None, []
    if not isinstance(receipts, list):
        return "indeterminate", None, []
    expected_binding = {
        field: copy.deepcopy(bundle[field])
        for field in BINDING_FIELDS
        if field in bundle
    }

    def belongs_to_selected_bundle(item):
        if not isinstance(item, dict):
            return False
        if any(item.get(field) != value for field, value in expected_binding.items()):
            return False
        return "nonce" in expected_binding or "nonce" not in item

    candidates = [item for item in receipts if belongs_to_selected_bundle(item)]

    def receipt_verifier(item):
        return inspect_anchor_receipt(
            item,
            expected_binding=expected_binding,
            adapter_domain=ANCHOR_ADAPTER_DOMAIN,
            adapter_policy=ANCHOR_POLICY,
            trusted_adapter=TRUSTED_ANCHOR_ADAPTER,
            authorized_signer=bundle.get("writer"),
        )

    return resolve_shared_anchor_history(
        selected,
        candidates,
        expected_binding=expected_binding,
        receipt_verifier=receipt_verifier,
        expected_lineage_root=bundle["transactionRef"],
        allow_implicit_selection=selected is None,
    )


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


def resolve_current(data, receipts, outcome_evidence, *, selected_anchor=None):
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

    anchor_status, anchor, anchor_history = resolve_anchor_history(
        bundle, receipts, selected=selected_anchor
    )
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
            "standaloneAWT": True,
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
            selected_anchor=replay.get("anchorReceipt"),
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
            "awt-malformed-block-ref-missing-id-indeterminate",
            "awt-malformed-block-height-empty-indeterminate",
            "awt-malformed-block-height-non-decimal-indeterminate",
            "awt-malformed-block-height-signed-indeterminate",
            "awt-malformed-block-height-plus-indeterminate",
            "awt-malformed-block-height-space-indeterminate",
            "awt-malformed-block-height-unicode-digit-indeterminate",
            "awt-malformed-block-height-leading-zero-indeterminate",
            "awt-malformed-block-height-decimal-indeterminate",
            "awt-malformed-block-height-exponent-indeterminate",
            "awt-malformed-replacement-proof-container-indeterminate",
            "awt-malformed-replacement-kind-container-indeterminate",
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

    def test_height_grammar_and_compressed_finality_vectors(self):
        vectors = {item["name"]: item for item in self.document["vectors"]}
        for name in (
            "awt-finalized-anchor-without-height-pass",
            "awt-included-anchor-without-height-pass",
            "awt-finalized-anchor-canonical-decimal-height-pass",
        ):
            with self.subTest(vector=name):
                self.assertEqual(evaluate(vectors[name])["expected"], "pass")
        for name in (
            "awt-malformed-block-ref-missing-id-indeterminate",
            "awt-malformed-block-height-container-indeterminate",
            "awt-malformed-block-height-empty-indeterminate",
            "awt-malformed-block-height-non-decimal-indeterminate",
            "awt-malformed-block-height-signed-indeterminate",
            "awt-malformed-block-height-plus-indeterminate",
            "awt-malformed-block-height-space-indeterminate",
            "awt-malformed-block-height-unicode-digit-indeterminate",
            "awt-malformed-block-height-leading-zero-indeterminate",
            "awt-malformed-block-height-decimal-indeterminate",
            "awt-malformed-block-height-exponent-indeterminate",
        ):
            with self.subTest(vector=name):
                self.assertEqual(evaluate(vectors[name])["expected"], "indeterminate")
        for name in (
            "awt-compressed-finality-submitted-to-finalized-pass",
            "awt-compressed-finality-accepted-to-finalized-pass",
        ):
            with self.subTest(vector=name):
                result = evaluate(vectors[name])
                self.assertEqual(result["expected"], "pass")
                self.assertTrue(result["want"]["countable"])
        for name in (
            "awt-submitted-to-finalized-undeclared-profile-indeterminate",
            "awt-accepted-to-finalized-undeclared-profile-indeterminate",
            "awt-cross-profile-finality-history-indeterminate",
            "awt-compressed-finality-finalized-then-reorg-indeterminate",
        ):
            with self.subTest(vector=name):
                result = evaluate(vectors[name])
                self.assertEqual(result["expected"], "indeterminate")
                self.assertFalse(result["want"]["countable"])

    def test_awt_uses_shared_signed_portable_receipt_adapter(self):
        vectors = {item["name"]: item for item in self.document["vectors"]}
        data = vectors["awt-finalized-exact-replacement-pass"]["input"]
        expected_binding = {
            field: copy.deepcopy(data["bundle"][field]) for field in BINDING_FIELDS
        }
        for receipt in data["knownReceipts"]:
            with self.subTest(transaction=receipt["transactionRef"]):
                self.assertNotIn("nativeOrder", receipt)
                self.assertNotIn("replacementRelation", receipt)
                adapter = decode_canonical_object(receipt["evidence"]["value"])
                self.assertIsInstance(adapter, dict)
                self.assertEqual(
                    adapter["lineageRootTransactionRef"],
                    data["bundle"]["transactionRef"],
                )
                self.assertEqual(
                    inspect_anchor_receipt(
                        receipt,
                        expected_binding=expected_binding,
                        adapter_domain=ANCHOR_ADAPTER_DOMAIN,
                        adapter_policy=ANCHOR_POLICY,
                        trusted_adapter=TRUSTED_ANCHOR_ADAPTER,
                        authorized_signer=data["bundle"]["writer"],
                    )[0],
                    "pass",
                )

        replay = vectors["awt-replay-concrete-gate-pass"]["input"]["replayContext"]
        self.assertIn(replay["anchorReceipt"], replay["anchorReceiptHistory"])
        self.assertEqual(
            replay["anchorReceipt"]["transactionRef"]["value"], "tx-window-b"
        )

    def test_generator_is_deterministic(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(GENERATOR),
                "--check",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_spec_pins_outcome_clock_and_legacy_boundary(self):
        text = SPEC.read_text(encoding="utf-8")
        self.assertIn("**DACS-5 v0.7**", text)
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
