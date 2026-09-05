#!/usr/bin/env python3
"""Generate DACS-5 v0.6 authenticated reputation-window vectors."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "reputation-authenticated-window-v0.6.json"
)
SET_NAME = "reputation-authenticated-window-v0.6"
SPEC = "DACS-5 v0.6 §10.5 AWT-1..AWT-8 authenticated reputation-window time"

ANCHOR_TRANSACTION_REF = {"kind": "demos-tx", "value": "tx-window-a"}
LEGACY_PROFILE_COMMIT = "3426faaebc09948d57a3a6d30fd6795df579b68f"
TRUSTED_ERA_POLICY = {
    "policyId": "dacs-test-era-policy-v1",
    "adapter": "conformance-harness-profile-era-v1",
    "authority": "did:demos:steward",
    "producer": "did:demos:legacy-reputation-producer",
    "sessionId": "01K4AWT0000000000000000001",
    "profile": "dacs-next-dacs-5-v0.5",
    "commit": LEGACY_PROFILE_COMMIT,
    "currentProfile": "dacs-next-dacs-5-v0.6",
    "revisionRelation": "predates-current",
}

BUNDLE = {
    "substrate": "demos:testnet",
    "logicalAddress": "stor-" + "11" * 32,
    "nativeAddress": "storage-program:window-bundle-a",
    "contentHash": "22" * 32,
    "writer": "demos1buyer",
    "nonce": "7",
    "transactionRef": copy.deepcopy(ANCHOR_TRANSACTION_REF),
}


def receipt(
    transaction: str = "tx-window-a",
    timestamp: int | None = 2_000,
    *,
    state: str = "finalized",
    disposition: str = "established",
    block_id: str = "block-20",
    native_order: int = 20,
    history: str = "canonical",
    bundle: dict | None = None,
) -> dict:
    bound_bundle = BUNDLE if bundle is None else bundle
    item = {
        "receiptVersion": "1",
        **copy.deepcopy(bound_bundle),
        "finalityProfile": "demos-bft-final",
        "transactionRef": {"kind": "demos-tx", "value": transaction},
        "state": state,
        "observationDisposition": disposition,
        "observedAt": 9_999_999,
        "evidence": {"kind": "demos-consensus-proof", "value": "proof-ok"},
        "evidenceValid": True,
        "nativeOrder": native_order,
        "historyDisposition": history,
    }
    if state in {"included", "finalized"}:
        item["blockRef"] = {"id": block_id, "height": str(native_order)}
        if timestamp is not None:
            item["blockRef"]["timestamp"] = timestamp
    return item


def current_input(receipts: list[dict] | None = None, **changes) -> dict:
    item = {
        "derivationDiscriminators": {"authenticatedWindowDerivationVersion": "1"},
        "windowingBasis": "sr2-finalized-inclusion-timestamp",
        "windowStart": 1_000,
        "windowEnd": 3_000,
        "bundleFinalisedAt": 2_000,
        "bundle": copy.deepcopy(BUNDLE),
        "knownReceipts": copy.deepcopy([receipt()] if receipts is None else receipts),
        "replayContext": None,
        "historicalPolicy": False,
        "trustedEraPolicy": None,
        "eraEvidence": None,
    }
    item.update(copy.deepcopy(changes))
    return item


def replacement_receipt(*, relation_valid: bool = True) -> dict:
    item = receipt(
        state="accepted", timestamp=None, history="replaced", native_order=18
    )
    replacement = {"kind": "demos-tx", "value": "tx-window-b"}
    item["replacementTransactionRef"] = replacement
    item["replacementRelation"] = {
        "kind": "demos-authenticated-replacement",
        "predecessor": copy.deepcopy(ANCHOR_TRANSACTION_REF),
        "replacement": copy.deepcopy(replacement),
        "evidenceValid": relation_valid,
    }
    return item


def canonical_history(receipts: list[dict]) -> list[dict]:
    """Order valid replay fixtures by native order and canonical-byte hash."""
    unique = {}
    for item in receipts:
        encoded = json.dumps(
            item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        unique[encoded] = item
    return [
        copy.deepcopy(item)
        for _, item in sorted(
            unique.items(),
            key=lambda pair: (
                pair[1]["nativeOrder"], hashlib.sha256(pair[0]).hexdigest()
            ),
        )
    ]


def replay_input(receipts: list[dict], selected: dict) -> dict:
    return current_input(
        receipts,
        replayContext={
            "windowReceipt": copy.deepcopy(selected),
            "windowReceiptHistory": canonical_history(receipts),
        },
    )


def verified_era_evidence() -> dict:
    return {
        "kind": "verified-profile-era-projection",
        "verificationDisposition": "verified",
        **copy.deepcopy(TRUSTED_ERA_POLICY),
    }


def historical_input(discriminator: str, *, verified: bool) -> dict:
    return current_input(
        derivationDiscriminators={discriminator: "1"},
        windowingBasis="finalisedAt",
        historicalPolicy=verified,
        trustedEraPolicy=copy.deepcopy(TRUSTED_ERA_POLICY) if verified else None,
        eraEvidence=verified_era_evidence() if verified else None,
    )


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
            "windowReceipt.blockRef.timestamp" if countable else None
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
            "awt-canonical-finalized-pass", "pass",
            "an independently verified finalized receipt supplies the exact bundle clock",
            current_input(), verified,
        ),
        vector(
            "awt-backdated-bad-outcome-still-in-window", "pass",
            "producer backdating cannot move a bad bundle out when consensus time remains inside",
            current_input(bundleFinalisedAt=999), verified,
        ),
        vector(
            "awt-future-dated-good-outcome-still-in-window", "pass",
            "producer future-dating cannot move a good bundle when consensus time remains inside",
            current_input(bundleFinalisedAt=3_001), verified,
        ),
        vector(
            "awt-backdated-good-outcome-does-not-enter", "pass",
            "an in-window producer time cannot import a bundle whose authenticated time is early",
            current_input([receipt(timestamp=999)], bundleFinalisedAt=2_000), outside_early,
        ),
        vector(
            "awt-future-dated-good-outcome-does-not-enter-late-window", "pass",
            "an in-window producer time cannot import a bundle whose authenticated time is late",
            current_input([receipt(timestamp=3_001)], bundleFinalisedAt=2_000), outside_late,
        ),
        vector(
            "awt-large-positive-clock-skew-advisory", "pass",
            "large positive finalisedAt skew is audit-only and does not change membership",
            current_input(bundleFinalisedAt=8_000_000), verified,
        ),
        vector(
            "awt-large-negative-clock-skew-advisory", "pass",
            "large negative finalisedAt skew is audit-only and does not change membership",
            current_input(bundleFinalisedAt=1), verified,
        ),
        vector(
            "awt-window-start-equality-inclusive", "pass",
            "consensus time exactly equal to windowStart is included",
            current_input([receipt(timestamp=1_000)]),
            want(countable=True, member=True, timestamp=1_000),
        ),
        vector(
            "awt-window-end-equality-inclusive", "pass",
            "consensus time exactly equal to windowEnd is included",
            current_input([receipt(timestamp=3_000)]),
            want(countable=True, member=True, timestamp=3_000),
        ),
        vector(
            "awt-observed-at-never-controls-window", "pass",
            "observer wall-clock time is ignored even when far outside the window",
            current_input(), verified,
        ),
        vector(
            "awt-missing-receipt-indeterminate", "indeterminate",
            "no receipt makes the job non-countable without a producer-time fallback",
            current_input([]), indeterminate,
        ),
        vector(
            "awt-finalized-receipt-missing-timestamp", "indeterminate",
            "a finalized receipt without blockRef.timestamp cannot supply the clock",
            current_input([receipt(timestamp=None)]), indeterminate,
        ),
        vector(
            "awt-accepted-is-not-clock", "indeterminate",
            "durable acceptance has no consensus inclusion clock",
            current_input([receipt(state="accepted")]), indeterminate,
        ),
        vector(
            "awt-included-without-finality-insufficient", "indeterminate",
            "included is not enough where the binding has not established finality",
            current_input([receipt(state="included")]), indeterminate,
        ),
        vector(
            "awt-indeterminate-finalized-observation-insufficient", "indeterminate",
            "an indeterminate snapshot cannot establish finalized time on its own",
            current_input([receipt(disposition="indeterminate")]), indeterminate,
        ),
        vector(
            "awt-invalid-native-proof-indeterminate", "indeterminate",
            "receipt fields without valid native evidence do not authenticate time",
            current_input([{**receipt(), "evidenceValid": False}]), indeterminate,
        ),
    ]

    for field, value in (
        ("substrate", "other:testnet"),
        ("logicalAddress", "stor-" + "33" * 32),
        ("nativeAddress", "storage-program:other"),
        ("contentHash", "44" * 32),
        ("writer", "demos1attacker"),
        ("nonce", "8"),
    ):
        mismatched = receipt()
        mismatched[field] = value
        vectors.append(vector(
            f"awt-{field.lower()}-mismatch-indeterminate", "indeterminate",
            f"a receipt whose {field} does not bind the exact selected bundle is unusable",
            current_input([mismatched]), indeterminate,
        ))

    replaced = replacement_receipt()
    unverified_replacement = replacement_receipt(relation_valid=False)
    vectors += [
        vector(
            "awt-wrong-sole-transaction-indeterminate", "indeterminate",
            "a finalized receipt for an unrelated transaction does not bind the selected anchor",
            current_input([receipt("tx-unrelated")]), indeterminate,
        ),
        vector(
            "awt-replaced-original-without-final-replacement", "indeterminate",
            "a replaced transaction is inert until its replacement independently finalizes",
            current_input([replaced]), indeterminate,
        ),
        vector(
            "awt-finalized-replacement-without-authenticated-relation", "indeterminate",
            "a finalized replacement is unusable when its predecessor relation is not authenticated",
            current_input([
                unverified_replacement,
                receipt("tx-window-b", native_order=21, block_id="block-21"),
            ]), indeterminate,
        ),
        vector(
            "awt-finalized-exact-replacement-pass", "pass",
            "the exact-content replacement supplies its own finalized inclusion clock",
            current_input([replaced, receipt("tx-window-b", native_order=21, block_id="block-21")]),
            verified,
        ),
        vector(
            "awt-reorg-without-finalized-reentry", "indeterminate",
            "a reorged inclusion cannot supply current window time",
            current_input([receipt(state="included", history="reorged")]), indeterminate,
        ),
        vector(
            "awt-reorg-then-finalized-reentry-pass", "pass",
            "authenticated re-entry followed by finality supplies the new canonical clock",
            current_input([
                receipt(state="included", history="reorged", native_order=20),
                receipt(timestamp=2_100, native_order=21, block_id="block-21"),
            ]),
            want(countable=True, member=True, timestamp=2_100),
        ),
        vector(
            "awt-finalized-then-reorg-conflict", "indeterminate",
            "a history purporting to reorg a terminal finalized transaction is conflicting",
            current_input([
                receipt(native_order=20),
                receipt(state="included", history="reorged", native_order=21),
            ]), indeterminate,
        ),
        vector(
            "awt-duplicate-identical-finalized-snapshots-collapse", "pass",
            "byte-equivalent observations of one finalized event collapse deterministically",
            current_input([receipt(), receipt()]), verified,
        ),
        vector(
            "awt-two-finalized-transactions-conflict", "indeterminate",
            "two authenticated surviving finalized transaction identities cannot be cherry-picked",
            current_input([
                receipt(), replaced,
                receipt("tx-window-b", native_order=21, block_id="block-21"),
            ]), indeterminate,
        ),
        vector(
            "awt-same-transaction-conflicting-blocks", "indeterminate",
            "otherwise-valid finalized receipts disagreeing on block identity are unorderable",
            current_input([receipt(), receipt(block_id="block-21", native_order=21)]), indeterminate,
        ),
        vector(
            "awt-same-event-conflicting-timestamps", "indeterminate",
            "otherwise-valid receipts disagreeing on the event timestamp are unorderable",
            current_input([receipt(), receipt(timestamp=2_001)]), indeterminate,
        ),
        vector(
            "awt-conflicting-native-order", "indeterminate",
            "otherwise-valid receipts disagreeing on native order do not admit min/max selection",
            current_input([receipt(), receipt(native_order=21)]), indeterminate,
        ),
        vector(
            "awt-explicit-unorderable-history", "indeterminate",
            "the binding's unorderable conflict disposition makes the job non-countable",
            current_input([receipt(history="unorderable")]), indeterminate,
        ),
        vector(
            "awt-wrong-current-window-basis", "error",
            "the current discriminator accepts only its single finalized-inclusion basis",
            current_input(windowingBasis="finalisedAt"), indeterminate,
        ),
        vector(
            "awt-current-plus-legacy-discriminator", "error",
            "multiple derivation discriminators are rejected before metrics are used",
            current_input(derivationDiscriminators={
                "authenticatedWindowDerivationVersion": "1", "derivationVersion": "1",
            }), indeterminate,
        ),
        vector(
            "awt-missing-current-discriminator", "error",
            "a derivation with no discriminator cannot claim current-profile semantics",
            current_input(derivationDiscriminators={}), indeterminate,
        ),
        vector(
            "awt-wrong-current-discriminator-version", "fail",
            "an unsupported current-profile version is not reinterpreted as version 1",
            current_input(derivationDiscriminators={
                "authenticatedWindowDerivationVersion": "2",
            }),
            want(countable=False, member=False, timestamp=None, current=False),
        ),
        vector(
            "awt-unknown-derivation-discriminator", "fail",
            "an unknown derivation type is rejected rather than structurally downgraded",
            current_input(derivationDiscriminators={"futureDerivationVersion": "1"}),
            want(countable=False, member=False, timestamp=None, current=False),
        ),
        vector(
            "awt-legacy-producer-time-is-not-era-evidence", "fail",
            "computedAt and finalisedAt cannot authenticate a pre-current production era",
            current_input(
                derivationDiscriminators={"replayableDerivationVersion": "1"},
                windowingBasis="finalisedAt", historicalPolicy=True,
                eraEvidence={"kind": "producer-assertion", "authenticated": False},
            ),
            want(countable=False, member=False, timestamp=None, current=False),
        ),
    ]

    replay_receipts = [
        replaced,
        receipt("tx-window-b", native_order=21, block_id="block-21"),
    ]
    selected_replay_receipt = replay_receipts[1]
    valid_replay = replay_input(replay_receipts, selected_replay_receipt)
    vectors.append(vector(
        "awt-replay-concrete-history-pass", "pass",
        "replay re-verifies the selected replacement and its native-ordered concrete history",
        valid_replay, verified,
    ))

    missing_selected = copy.deepcopy(valid_replay)
    missing_selected["replayContext"].pop("windowReceipt")
    vectors.append(vector(
        "awt-replay-missing-selected-receipt", "fail",
        "replay refuses context that omits the exact receipt used for membership",
        missing_selected, indeterminate,
    ))

    missing_history = copy.deepcopy(valid_replay)
    missing_history["replayContext"].pop("windowReceiptHistory")
    vectors.append(vector(
        "awt-replay-missing-receipt-history", "fail",
        "replay refuses context that omits the receipt history used for conflict checks",
        missing_history, indeterminate,
    ))

    substituted_timestamp = copy.deepcopy(valid_replay)
    substituted_timestamp["replayContext"]["windowReceipt"]["blockRef"]["timestamp"] = 2_001
    vectors.append(vector(
        "awt-replay-substituted-timestamp", "fail",
        "replay refuses a concrete selected receipt with a substituted timestamp",
        substituted_timestamp, indeterminate,
    ))

    substituted_transaction = copy.deepcopy(valid_replay)
    substituted_transaction["replayContext"]["windowReceipt"]["transactionRef"] = {
        "kind": "demos-tx", "value": "tx-attacker"
    }
    vectors.append(vector(
        "awt-replay-substituted-transaction", "fail",
        "replay refuses a selected receipt rebound to another transaction",
        substituted_transaction, indeterminate,
    ))

    substituted_proof = copy.deepcopy(valid_replay)
    substituted_proof["replayContext"]["windowReceipt"]["evidence"]["value"] = "proof-other"
    vectors.append(vector(
        "awt-replay-substituted-native-proof", "fail",
        "replay refuses changed concrete native proof bytes",
        substituted_proof, indeterminate,
    ))

    misordered_history = copy.deepcopy(valid_replay)
    misordered_history["replayContext"]["windowReceiptHistory"].reverse()
    vectors.append(vector(
        "awt-replay-misordered-history", "fail",
        "replay refuses concrete history ordered opposite binding-native order",
        misordered_history, indeterminate,
    ))

    malformed_receipts = []
    for name, note, mutate in (
        ("transaction-ref-array", "a non-object transactionRef fails closed", lambda r: r.__setitem__("transactionRef", [])),
        ("block-ref-array", "a non-object blockRef fails closed", lambda r: r.__setitem__("blockRef", [])),
        ("timestamp-string", "a non-integer block timestamp fails closed", lambda r: r["blockRef"].__setitem__("timestamp", "2000")),
        ("timestamp-container", "a container block timestamp fails closed", lambda r: r["blockRef"].__setitem__("timestamp", [])),
        ("native-order-container", "a container native order fails closed", lambda r: r.__setitem__("nativeOrder", [])),
        ("history-disposition-container", "a container history disposition fails closed", lambda r: r.__setitem__("historyDisposition", [])),
        ("native-evidence-array", "a non-object native evidence projection fails closed", lambda r: r.__setitem__("evidence", [])),
    ):
        malformed = receipt()
        mutate(malformed)
        malformed_receipts.append(vector(
            f"awt-malformed-{name}-indeterminate", "indeterminate", note,
            current_input([malformed]), indeterminate,
        ))
    vectors.extend(malformed_receipts)

    legacy_want = want(
        countable=False, member=False, timestamp=None, current=False, historical=True
    )
    rejected_legacy_want = want(
        countable=False, member=False, timestamp=None, current=False
    )
    for discriminator, slug in (
        ("derivationVersion", "derivation"),
        ("replayableDerivationVersion", "replayable-derivation"),
        ("jobBoundReplayableDerivationVersion", "job-bound-replayable-derivation"),
        ("settlementVerifiedDerivationVersion", "settlement-verified-derivation"),
        (
            "replayableSettlementVerifiedDerivationVersion",
            "replayable-settlement-verified-derivation",
        ),
    ):
        vectors.append(vector(
            f"awt-{slug}-cannot-claim-current", "fail",
            f"{discriminator} cannot satisfy a current-profile request",
            historical_input(discriminator, verified=False), rejected_legacy_want,
        ))
        vectors.append(vector(
            f"awt-{slug}-verified-era-is-historical-only", "pass",
            f"a verified exact pre-current profile may admit {discriminator} only as historical/partial",
            historical_input(discriminator, verified=True), legacy_want,
        ))

    for field, value in (
        ("verificationDisposition", "unverified"),
        ("producer", "did:demos:other-producer"),
        ("sessionId", "01K4AWT0000000000000000002"),
        ("profile", "dacs-next-dacs-5-v0.4"),
        ("commit", "0" * 40),
        ("revisionRelation", "same-as-current"),
    ):
        mismatched_era = historical_input("replayableDerivationVersion", verified=True)
        mismatched_era["eraEvidence"][field] = value
        vectors.append(vector(
            f"awt-era-{field.lower()}-mismatch-rejected", "fail",
            f"the verified era projection must bind exact {field} to trusted policy",
            mismatched_era, rejected_legacy_want,
        ))

    mismatched_policy = historical_input("replayableDerivationVersion", verified=True)
    mismatched_policy["trustedEraPolicy"]["policyId"] = "attacker-policy"
    vectors.append(vector(
        "awt-era-trust-policy-mismatch-rejected", "fail",
        "caller-selected trust policy cannot authenticate a historical profile",
        mismatched_policy, rejected_legacy_want,
    ))

    coordinated_tampering = historical_input(
        "replayableDerivationVersion", verified=True
    )
    coordinated_tampering["trustedEraPolicy"]["policyId"] = "attacker-policy"
    coordinated_tampering["eraEvidence"]["policyId"] = "attacker-policy"
    vectors.append(vector(
        "awt-era-coordinated-policy-and-evidence-tampering-rejected", "fail",
        "the harness trust anchor is immutable even when caller policy and evidence agree",
        coordinated_tampering, rejected_legacy_want,
    ))
    return vectors


def document() -> dict:
    vectors = build_vectors()
    encoded = json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()
    return {
        "set": SET_NAME,
        "spec": SPEC,
        "decisionModel": (
            "pass may count an in-window job or deterministically exclude an out-of-window job; "
            "indeterminate is always non-countable; error/fail cannot satisfy the current profile"
        ),
        "inputModel": (
            "one post-reconciliation authoritative bundle and all known SR-2 receipt snapshots; "
            "the corpus executes AWT-6 membership after that disclosed precondition but does not "
            "independently execute two-copy reconciliation ordering; evidenceValid, authenticated "
            "replacement relations, historyDisposition, and nativeOrder model binding-authenticated "
            "native verification"
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
