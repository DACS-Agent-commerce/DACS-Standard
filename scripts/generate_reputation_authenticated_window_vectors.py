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

BUNDLE = {
    "substrate": "demos:testnet",
    "logicalAddress": "stor-" + "11" * 32,
    "nativeAddress": "storage-program:window-bundle-a",
    "contentHash": "22" * 32,
    "writer": "demos1buyer",
    "nonce": "7",
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
) -> dict:
    item = {
        "receiptVersion": "1",
        **copy.deepcopy(BUNDLE),
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
        "replayMutation": None,
        "historicalPolicy": False,
        "eraEvidence": None,
    }
    item.update(copy.deepcopy(changes))
    return item


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

    replaced = receipt(state="accepted", timestamp=None, history="replaced", native_order=18)
    replaced["replacementTransactionRef"] = {"kind": "demos-tx", "value": "tx-window-b"}
    vectors += [
        vector(
            "awt-replaced-original-without-final-replacement", "indeterminate",
            "a replaced transaction is inert until its replacement independently finalizes",
            current_input([replaced]), indeterminate,
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
            "two surviving finalized transaction identities cannot be cherry-picked",
            current_input([receipt(), receipt("tx-window-b")]), indeterminate,
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
            "awt-replay-missing-selected-receipt", "fail",
            "replay refuses context that omits the exact receipt used for membership",
            current_input(replayMutation="omit-windowReceipt"), indeterminate,
        ),
        vector(
            "awt-replay-missing-receipt-history", "fail",
            "replay refuses context that omits the receipt history used for conflict checks",
            current_input(replayMutation="omit-windowReceiptHistory"), indeterminate,
        ),
        vector(
            "awt-replay-substituted-timestamp", "fail",
            "replay refuses substitution of a different authenticated timestamp",
            current_input(replayMutation="substitute-blockRef.timestamp"), indeterminate,
        ),
        vector(
            "awt-replay-misordered-history", "fail",
            "replay refuses receipt history ordered by observer time instead of native order",
            current_input(replayMutation="misorder-windowReceiptHistory"), indeterminate,
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
            "awt-legacy-is-not-current", "fail",
            "a released derivation cannot satisfy a current-profile request",
            current_input(
                derivationDiscriminators={"derivationVersion": "1"},
                windowingBasis="finalisedAt",
            ),
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
        vector(
            "awt-legacy-authenticated-era-historical-only", "pass",
            "authenticated profile pinning may admit a legacy receipt only as historical/partial",
            current_input(
                derivationDiscriminators={"replayableDerivationVersion": "1"},
                windowingBasis="finalisedAt", historicalPolicy=True,
                eraEvidence={
                    "kind": "authenticated-profile-commit",
                    "authenticated": True,
                    "commit": "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091",
                    "profile": "dacs-5-v0.3",
                },
            ),
            want(
                countable=False, member=False, timestamp=None,
                current=False, historical=True,
            ),
        ),
    ]
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
            "evidenceValid/historyDisposition/nativeOrder model binding-authenticated native verification"
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
