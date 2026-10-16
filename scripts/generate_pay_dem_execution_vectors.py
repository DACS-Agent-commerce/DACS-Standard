#!/usr/bin/env python3
"""Generate DACS-4 §9.5.9 DEM-1..DEM-7 pay-dem execution vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/vectors/security/pay-dem-execution-v0.1.json"
_OMIT = object()


def _hex(label: str) -> str:
    return hashlib.sha256(("pay-dem-execution:v0.1:" + label).encode()).hexdigest()


TX_HASH = _hex("tx")
OTHER_TX_HASH = _hex("other-tx")
SENDER = "0x" + _hex("payer")
RECIPIENT = "0x" + _hex("payee")
OTHER_ADDRESS = "0x" + _hex("other-address")
AMOUNT_OS = "1500000000"  # 1.5 DEM at 10^9 OS per DEM
OTHER_AMOUNT_OS = "1500000001"
NONCE = 9
BLOCK = 42


def _apply(base: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    value = dict(base)
    for key, item in changes.items():
        if item is _OMIT:
            value.pop(key, None)
        else:
            value[key] = item
    return value


def retained(**changes: Any) -> dict[str, Any]:
    return _apply(
        {
            "txHash": TX_HASH,
            "nonce": NONCE,
            "sender": SENDER,
            "recipient": RECIPIENT,
            "amountOs": AMOUNT_OS,
        },
        changes,
    )


def record(status: str = "confirmed", **changes: Any) -> dict[str, Any]:
    return _apply(
        {
            "txHash": TX_HASH,
            "nonce": NONCE,
            "blockNumber": BLOCK,
            "sender": SENDER,
            "recipient": RECIPIENT,
            "amountOs": AMOUNT_OS,
            "status": status,
        },
        changes,
    )


def found(value: dict[str, Any], *, authenticated: bool | None = None) -> dict[str, Any]:
    read: dict[str, Any] = {"state": "found", "record": value}
    if authenticated is not None:
        read["authenticated"] = authenticated
    return read


NOT_FOUND = {"state": "not-found"}
UNAVAILABLE = {"state": "unavailable"}
INCLUDED_AT_BLOCK = {"blockNumber": BLOCK}


def handler_want(expected: str) -> dict[str, Any]:
    return {
        "executionState": {"pass": "executed", "fail": "failed"}.get(
            expected, "indeterminate"
        ),
        "handlerResult": {"pass": "ok", "fail": "permanent"}.get(
            expected, "unresolved"
        ),
        "evidence": {
            "pass": "success-bft-final",
            "fail": "failure-without-settlement-finality",
        }.get(expected, "none"),
        "nextAction": {
            "pass": "anchor-success-evidence",
            "fail": "terminal-failure",
        }.get(expected, "re-read-retained-hash"),
        "terminalFailureProofRetained": expected == "fail",
        "deliveryAuthorized": expected == "pass",
        "settlementAccounting": expected == "pass",
        "broadcastPermitted": False,
        "replacementPermitted": False,
    }


def classify(
    name: str,
    expected: str,
    rule: str,
    guards: list[str],
    note: str,
    *,
    read: dict[str, Any],
    status_index: str = "included",
    inclusion: dict[str, Any] | None = INCLUDED_AT_BLOCK,
    transfer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "operation": "classify-execution",
        "protocolInput": {
            "retainedTransfer": retained() if transfer is None else transfer,
            "statusIndex": status_index,
            "inclusionObservation": inclusion,
            "recordRead": read,
        },
        "expected": expected,
        "want": handler_want(expected),
        "rule": "DACS-4 §9.5.9 " + rule,
        "guards": guards,
        "note": note,
    }


def failure_proof(**record_changes: Any) -> dict[str, Any]:
    return {
        "classification": "permanent",
        "inclusionBlock": BLOCK,
        "record": record("failed", **record_changes),
    }


def resume(
    name: str,
    expected: str,
    rule: str,
    guards: list[str],
    note: str,
    *,
    proof: dict[str, Any] | None,
    read: dict[str, Any],
    status_index: str = "included",
    inclusion: dict[str, Any] | None = INCLUDED_AT_BLOCK,
) -> dict[str, Any]:
    return {
        "name": name,
        "operation": "resume-phase",
        "protocolInput": {
            "retainedTransfer": retained(),
            "retainedFailureProof": proof,
            "statusIndex": status_index,
            "inclusionObservation": inclusion,
            "recordRead": read,
        },
        "expected": expected,
        "want": handler_want(expected),
        "rule": "DACS-4 §9.5.9 " + rule,
        "guards": guards,
        "note": note,
    }


def gate(
    name: str,
    expected: str,
    rule: str,
    guards: list[str],
    note: str,
    *,
    transfer: dict[str, Any] | None = None,
    durable: bool = True,
    broadcast_state: str = "never-broadcast",
    request: str = "broadcast-retained",
) -> dict[str, Any]:
    return {
        "name": name,
        "operation": "broadcast-gate",
        "protocolInput": {
            "retainedTransfer": retained() if transfer is None else transfer,
            "retentionDurable": durable,
            "broadcastState": broadcast_state,
            "request": request,
        },
        "expected": expected,
        "want": {"broadcastPermitted": expected == "pass"},
        "rule": "DACS-4 §9.5.9 " + rule,
        "guards": guards,
        "note": note,
    }


def admit(
    name: str,
    expected: str,
    rule: str,
    guards: list[str],
    note: str,
    *,
    read: dict[str, Any],
    status_index: str = "included",
) -> dict[str, Any]:
    return {
        "name": name,
        "operation": "admit-evidence",
        "protocolInput": {
            "signedEvidence": {
                "outcome": "success",
                "txRef": {"kind": "demos", "txHash": TX_HASH, "blockNumber": BLOCK},
            },
            "phase": {"payer": SENDER, "payee": RECIPIENT, "amountOs": AMOUNT_OS},
            "statusIndex": status_index,
            "recordRead": read,
        },
        "expected": expected,
        "want": {
            "admitted": expected == "pass",
            "deliveryAuthorized": expected == "pass",
        },
        "rule": "DACS-4 §9.5.9 " + rule,
        "guards": guards,
        "note": note,
    }


def build_vectors() -> list[dict[str, Any]]:
    unbound = "DEM-2/DEM-5"
    return [
        # Handler classification: the bound record decides, never the index.
        classify(
            "included-confirmed", "pass", "DEM-3", ["success-branch"],
            "A bound confirmed record is the only success; evidence and delivery follow.",
            read=found(record("confirmed")),
        ),
        classify(
            "included-failed", "fail", "DEM-4/DEM-6", ["failure-is-permanent", "failure-proof-retained", "no-replacement", "success-requires-record"],
            "Included is not executed: a bound failed record is a durable permanent failure with no replacement.",
            read=found(record("failed")),
        ),
        classify(
            "included-pending", "indeterminate", "DEM-5", ["success-requires-record", "unresolved-authorizes-nothing"],
            "Included with a pending record is unresolved and authorizes nothing.",
            read=found(record("pending")),
        ),
        classify(
            "included-record-not-found", "indeterminate", "DEM-5/DEM-6", ["no-rebroadcast", "success-requires-record", "unresolved-authorizes-nothing"],
            "Included but no record for the retained hash: execution is unknown and nothing is resent.",
            read=NOT_FOUND,
        ),
        classify(
            "included-record-unavailable", "indeterminate", "DEM-5", ["success-requires-record", "unresolved-authorizes-nothing"],
            "An unreachable node leaves execution unknown; no success, failure or delivery.",
            read=UNAVAILABLE,
        ),
        classify(
            "included-alias", "indeterminate", "DEM-3", ["success-requires-exact-confirmed", "success-requires-record", "unresolved-authorizes-nothing"],
            "A record status copied from the index label is not an execution result.",
            read=found(record("included")),
        ),
        classify(
            "finalized-alias", "indeterminate", "DEM-3", ["success-requires-exact-confirmed", "success-requires-record", "unresolved-authorizes-nothing"],
            "Finality vocabulary is not the executed record status.",
            read=found(record("finalized")),
        ),
        classify(
            "success-alias", "indeterminate", "DEM-3", ["success-requires-exact-confirmed", "success-requires-record", "unresolved-authorizes-nothing"],
            "Only the exact Demos record status confirmed establishes execution.",
            read=found(record("success")),
        ),
        classify(
            "confirmed-case-variant", "indeterminate", "DEM-3", ["success-requires-exact-confirmed", "success-requires-record", "unresolved-authorizes-nothing"],
            "Status comparison is exact; a case variant is unknown.",
            read=found(record("Confirmed")),
        ),
        classify(
            "confirmed-wrong-hash", "indeterminate", unbound, ["bind-hash", "success-requires-record", "unresolved-authorizes-nothing"],
            "A confirmed record for another hash says nothing about the retained transfer.",
            read=found(record("confirmed", txHash=OTHER_TX_HASH)),
        ),
        classify(
            "confirmed-wrong-nonce", "indeterminate", unbound, ["bind-nonce", "success-requires-record", "unresolved-authorizes-nothing"],
            "A record whose nonce differs from the signed nonce is unbound.",
            read=found(record("confirmed", nonce=NONCE + 1)),
        ),
        classify(
            "confirmed-wrong-block", "indeterminate", unbound, ["bind-block", "success-requires-record", "unresolved-authorizes-nothing"],
            "A record in a different block from the inclusion observation is unbound.",
            read=found(record("confirmed", blockNumber=BLOCK + 1)),
        ),
        classify(
            "confirmed-wrong-sender", "indeterminate", unbound, ["bind-sender", "success-requires-record", "unresolved-authorizes-nothing"],
            "A record debiting another sender is unbound.",
            read=found(record("confirmed", sender=OTHER_ADDRESS)),
        ),
        classify(
            "confirmed-wrong-recipient", "indeterminate", unbound, ["bind-recipient", "success-requires-record", "unresolved-authorizes-nothing"],
            "A record paying another recipient is unbound.",
            read=found(record("confirmed", recipient=OTHER_ADDRESS)),
        ),
        classify(
            "confirmed-wrong-amount", "indeterminate", unbound, ["bind-amount", "success-requires-record", "unresolved-authorizes-nothing"],
            "A record for a different OS amount is unbound.",
            read=found(record("confirmed", amountOs=OTHER_AMOUNT_OS)),
        ),
        classify(
            "confirmed-missing-nonce", "indeterminate", unbound, ["bind-nonce", "success-requires-record", "unresolved-authorizes-nothing"],
            "A record missing its nonce is unbound.",
            read=found(record("confirmed", nonce=_OMIT)),
        ),
        classify(
            "confirmed-float-nonce", "indeterminate", unbound, ["bind-exact-type", "bind-nonce", "success-requires-record", "unresolved-authorizes-nothing"],
            "Binding compares exact JSON types: 9.0 is not the signed integer nonce 9.",
            read=found(record("confirmed", nonce=float(NONCE))),
        ),
        classify(
            "confirmed-boolean-nonce", "indeterminate", unbound, ["bind-exact-type", "bind-nonce", "success-requires-record", "unresolved-authorizes-nothing"],
            "Binding compares exact JSON types: true is not the signed nonce 1.",
            read=found(record("confirmed", nonce=True)),
            transfer=retained(nonce=1),
        ),
        classify(
            "confirmed-without-inclusion-observation", "indeterminate", unbound, ["bind-block", "bind-requires-inclusion"],
            "Without an inclusion observation the record's block cannot be bound.",
            read=found(record("confirmed")), status_index="pending", inclusion=None,
        ),
        classify(
            "failed-wrong-nonce", "indeterminate", unbound, ["bind-nonce", "failure-requires-binding", "success-requires-record", "unresolved-authorizes-nothing"],
            "A failed record with another nonce does not prove this transfer failed.",
            read=found(record("failed", nonce=NONCE + 1)),
        ),
        classify(
            "failed-missing-nonce", "indeterminate", unbound, ["bind-nonce", "failure-requires-binding", "success-requires-record", "unresolved-authorizes-nothing"],
            "A failed record missing its nonce does not prove this transfer failed.",
            read=found(record("failed", nonce=_OMIT)),
        ),
        classify(
            "failed-wrong-block", "indeterminate", unbound, ["bind-block", "failure-requires-binding", "success-requires-record", "unresolved-authorizes-nothing"],
            "A failed record in another block conflicts with the inclusion observation.",
            read=found(record("failed", blockNumber=BLOCK + 1)),
        ),
        classify(
            "failed-wrong-amount", "indeterminate", unbound, ["bind-amount", "failure-requires-binding", "success-requires-record", "unresolved-authorizes-nothing"],
            "A failed record for another amount does not prove this transfer failed.",
            read=found(record("failed", amountOs=OTHER_AMOUNT_OS)),
        ),
        classify(
            "failed-wrong-hash", "indeterminate", unbound, ["bind-hash", "failure-requires-binding", "success-requires-record", "unresolved-authorizes-nothing"],
            "A failed record for another hash does not prove this transfer failed.",
            read=found(record("failed", txHash=OTHER_TX_HASH)),
        ),
        classify(
            "failed-without-inclusion-observation", "indeterminate", unbound, ["bind-block", "bind-requires-inclusion", "failure-requires-binding"],
            "A failed record without an inclusion observation is not a bound failure.",
            read=found(record("failed")), status_index="not-found", inclusion=None,
        ),
        classify(
            "transfer-unknown-not-rebroadcast", "indeterminate", "DEM-6", ["no-rebroadcast"],
            "Neither index nor record knows the hash; the handler still only re-reads.",
            read=NOT_FOUND, status_index="not-found", inclusion=None,
        ),
        # Recovery and resume.
        resume(
            "resume-reuses-failure-proof", "fail", "DEM-4/DEM-6", ["failure-proof-retained", "no-replacement", "resume-reuses-failure-proof"],
            "A resume after a proven failure reuses it even while the node is unreachable.",
            proof=failure_proof(), read=UNAVAILABLE,
        ),
        resume(
            "resume-corrupted-failure-proof", "indeterminate", "DEM-4/DEM-6", ["bind-nonce", "no-rebroadcast", "resume-validates-failure-proof", "success-requires-record", "unresolved-authorizes-nothing"],
            "A retained proof whose nonce no longer binds is not reused; re-read only.",
            proof=failure_proof(nonce=NONCE + 1), read=NOT_FOUND,
        ),
        resume(
            "resume-without-proof-not-found", "indeterminate", "DEM-6", ["no-rebroadcast"],
            "A crash after a possible broadcast resumes by re-reading, never resending.",
            proof=None, read=NOT_FOUND, status_index="not-found", inclusion=None,
        ),
        resume(
            "resume-without-proof-confirmed", "pass", "DEM-3/DEM-6", ["success-branch"],
            "Re-reading the retained hash finds the executed transfer; no second payment.",
            proof=None, read=found(record("confirmed")),
        ),
        # First-broadcast gate.
        gate(
            "first-broadcast-after-durable-retention", "pass", "DEM-1", ["first-broadcast-allowed"],
            "The single broadcast is allowed once all five values are durably retained.",
        ),
        gate(
            "broadcast-before-durable-retention", "fail", "DEM-1", ["broadcast-requires-durable-retention"],
            "Volatile retention cannot support recovery, so the broadcast is refused.",
            durable=False,
        ),
        gate(
            "broadcast-with-incomplete-retention", "error", "DEM-1", ["broadcast-requires-complete-retention"],
            "A retained transfer without its signed nonce is structurally incomplete.",
            transfer=retained(nonce=_OMIT),
        ),
        gate(
            "second-broadcast-refused", "fail", "DEM-6", ["no-rebroadcast"],
            "The same signed bytes are not sent again once they may have been broadcast.",
            broadcast_state="maybe-broadcast",
        ),
        gate(
            "replacement-broadcast-refused", "fail", "DEM-6", ["no-replacement"],
            "A replacement transfer is never sent for the same job phase.",
            broadcast_state="maybe-broadcast", request="broadcast-replacement",
        ),
        # Consumer admission, including the payee before delivery.
        admit(
            "consumer-confirmed-admitted", "pass", "DEM-7", ["consumer-admits-confirmed"],
            "A bound confirmed record satisfies DEM-7; other checks still apply.",
            read=found(record("confirmed")),
        ),
        admit(
            "consumer-included-only-refused", "indeterminate", "DEM-7", ["consumer-requires-confirmed-record"],
            "An included label without a record is not admitted as payment.",
            read=NOT_FOUND,
        ),
        admit(
            "consumer-pending-refused", "indeterminate", "DEM-7", ["consumer-requires-confirmed-record"],
            "A pending record is not admitted as payment.",
            read=found(record("pending")),
        ),
        admit(
            "consumer-unavailable-refused", "indeterminate", "DEM-7", ["consumer-requires-confirmed-record"],
            "An unreachable node supplies no execution result.",
            read=UNAVAILABLE,
        ),
        admit(
            "consumer-finalized-alias-refused", "indeterminate", "DEM-7", ["consumer-requires-confirmed-record", "success-requires-exact-confirmed"],
            "Only the exact confirmed status is admitted.",
            read=found(record("finalized")),
        ),
        admit(
            "consumer-failed-fails", "fail", "DEM-7", ["consumer-failed-refutes", "consumer-requires-confirmed-record"],
            "A bound failed record refutes the success evidence.",
            read=found(record("failed")),
        ),
        admit(
            "consumer-wrong-payee-unauthenticated", "indeterminate", "DEM-7", ["consumer-binding", "consumer-requires-confirmed-record"],
            "An unauthenticated read that pays another payee does not satisfy DEM-7.",
            read=found(record("confirmed", recipient=OTHER_ADDRESS), authenticated=False),
        ),
        admit(
            "consumer-wrong-block-unauthenticated", "indeterminate", "DEM-7", ["consumer-binding", "consumer-requires-confirmed-record"],
            "An unauthenticated read in another block does not satisfy DEM-7.",
            read=found(record("confirmed", blockNumber=BLOCK + 1), authenticated=False),
        ),
        admit(
            "consumer-wrong-payer-unauthenticated", "indeterminate", "DEM-7", ["consumer-binding", "consumer-requires-confirmed-record"],
            "An unauthenticated read from another payer does not satisfy DEM-7.",
            read=found(record("confirmed", sender=OTHER_ADDRESS), authenticated=False),
        ),
        admit(
            "consumer-wrong-amount-authenticated", "fail", "DEM-7/FV-5", ["consumer-authenticated-contradiction-fails", "consumer-binding", "consumer-requires-confirmed-record"],
            "Under FV-5 an authenticated record for another amount is fail.",
            read=found(record("confirmed", amountOs=OTHER_AMOUNT_OS), authenticated=True),
        ),
        admit(
            "consumer-wrong-payee-authenticated", "fail", "DEM-7/FV-5", ["consumer-authenticated-contradiction-fails", "consumer-binding", "consumer-requires-confirmed-record"],
            "Under FV-5 an authenticated record paying another payee is fail.",
            read=found(record("confirmed", recipient=OTHER_ADDRESS), authenticated=True),
        ),
    ]


def document() -> dict[str, Any]:
    vectors = build_vectors()
    encoded = json.dumps(
        vectors, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "set": "pay-dem-execution-v0.1",
        "spec": "DACS-4 §9.5.9 DEM-1..DEM-7; §9.5.1 PC-4/PC-7; §9.7.0 FV-5",
        "tier": "candidate",
        "description": (
            "Inclusion does not prove execution. Only a record bound to the "
            "retained hash, nonce, block, sender, recipient and OS amount with "
            "status confirmed succeeds; a bound failed record is a permanent "
            "failure; anything else stays indeterminate without a second broadcast."
        ),
        "fixtureVocabulary": {
            "statusIndex": "node status-index label for the retained hash; never decisive",
            "inclusionObservation": "block identified for the retained hash, or null",
            "recordRead": "transaction-record read: found, not-found or unavailable",
            "guards": "checks whose removal makes this vector fail",
        },
        "count": len(vectors),
        "hash": hashlib.sha256(encoded).hexdigest(),
        "vectors": vectors,
    }


def rendered() -> str:
    return json.dumps(document(), ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.write:
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)} ({document()['count']} vectors)")
        return 0
    try:
        actual = OUTPUT.read_text(encoding="utf-8")
    except FileNotFoundError:
        actual = ""
    if actual != expected:
        print("pay-dem execution vectors are stale; run with --write")
        return 1
    print(f"pay-dem execution vectors OK ({document()['count']} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
