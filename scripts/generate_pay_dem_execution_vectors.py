#!/usr/bin/env python3
"""Generate DACS-4 §9.5.9 DEM-1..DEM-7 pay-dem execution vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/vectors/security/pay-dem-execution-v0.1.json"
sys.path.insert(0, str(ROOT / "scripts"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from jcs import canonicalize  # noqa: E402
from demos_json import stringify  # noqa: E402

_OMIT = object()


def _hex(label: str) -> str:
    return hashlib.sha256(("pay-dem-execution:v0.1:" + label).encode()).hexdigest()


def _signing_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(_hex(label + "-seed")))


def _key(private: Ed25519PrivateKey) -> str:
    return private.public_key().public_bytes_raw().hex()


JOB_ID = "01JA2B3C4D5E6F7G8H9JKMNPQR"
OTHER_JOB_ID = "01JA2B3C4D5E6F7G8H9JKMNPQS"
PHASE_INDEX = 1
OTHER_TX_HASH = _hex("other-tx")
# DACS-1 Demos keys: 64 lowercase hex digits without `0x`. The payer and the
# other key sign, so they are real Ed25519 public keys.
PAYER_SIGNER = _signing_key("payer")
OTHER_SIGNER = _signing_key("other-address")
PAYER_KEY = _key(PAYER_SIGNER)
PAYEE_KEY = _hex("payee")
OTHER_KEY = _key(OTHER_SIGNER)
AMOUNT_OS = "1500000000"  # 1.5 DEM at 10^9 OS per DEM
OTHER_AMOUNT_OS = "1500000001"
NONCE = 9
BLOCK = 42
LARGE_AMOUNT_OS = "9007199254740993"  # above 2^53 - 1: the node serves a string

# Read-only node2.demos.sh `getTxByHash` responses, 2026-10-17. The node
# reported `stabilisation@61b8e75aa8db` (dirty). These are observations that
# exercise the profile on real wire bytes, not the normative source pin.
NODE2_CONFIRMED = json.loads(
    '{"content":{"type":"native","from":"0xc0a58599ceaeba18f9c450133631cce4c45f4dc7a59c8026331504da3a913c2a",'
    '"to":"0x706b89f5e2d56498a90bc3a209842b0bd0e22ce06bb4df7c27805e655614e5f1",'
    '"from_ed25519_address":"0xc0a58599ceaeba18f9c450133631cce4c45f4dc7a59c8026331504da3a913c2a",'
    '"amount":9500000000,"nonce":"28","timestamp":"1791649642726",'
    '"transaction_fee":{"network_fee":1000000000,"rpc_fee":1000000000,"additional_fee":0,"rpc_address":null},'
    '"data":["native",{"nativeOperation":"send","args":["706b89f5e2d56498a90bc3a209842b0bd0e22ce06bb4df7c27805e655614e5f1","9500000000"]}],'
    '"gcr_edits":[{"type":"balance","operation":"remove","isRollback":false,"account":"0xc0a58599ceaeba18f9c450133631cce4c45f4dc7a59c8026331504da3a913c2a","txhash":"330dcf1dac0839ebc138d5e2a0db6db7b9567d769c8d4bd987b0d72d7d905918","amount":"9500000000"},'
    '{"type":"balance","operation":"add","isRollback":false,"account":"0x706b89f5e2d56498a90bc3a209842b0bd0e22ce06bb4df7c27805e655614e5f1","txhash":"330dcf1dac0839ebc138d5e2a0db6db7b9567d769c8d4bd987b0d72d7d905918","amount":"9500000000"},'
    '{"type":"balance","account":"0xc0a58599ceaeba18f9c450133631cce4c45f4dc7a59c8026331504da3a913c2a","operation":"remove","amount":"1000000000","txhash":"330dcf1dac0839ebc138d5e2a0db6db7b9567d769c8d4bd987b0d72d7d905918","isRollback":false},'
    '{"type":"nonce","operation":"add","account":"0xc0a58599ceaeba18f9c450133631cce4c45f4dc7a59c8026331504da3a913c2a","amount":1,"txhash":"330dcf1dac0839ebc138d5e2a0db6db7b9567d769c8d4bd987b0d72d7d905918","isRollback":false}]},'
    '"signature":{"type":"ed25519","data":"0x2472d5b8de055b120224faf25c827afaca90f8c3e46e08f3a4f8bdd23fa72cdfd2972a28886781bf4522ee485e88e02ec5d0108d42a9e4af9a240154a4311a0f"},'
    '"ed25519_signature":null,"hash":"330dcf1dac0839ebc138d5e2a0db6db7b9567d769c8d4bd987b0d72d7d905918",'
    '"status":"confirmed","blockNumber":498447,"attrs":{"reference_block":498446}}'
)
NODE2_FAILED = json.loads(
    '{"content":{"type":"native","from":"0xc0a58599ceaeba18f9c450133631cce4c45f4dc7a59c8026331504da3a913c2a",'
    '"to":"0x706b89f5e2d56498a90bc3a209842b0bd0e22ce06bb4df7c27805e655614e5f1",'
    '"from_ed25519_address":"0xc0a58599ceaeba18f9c450133631cce4c45f4dc7a59c8026331504da3a913c2a",'
    '"amount":9500000000,"nonce":"9","timestamp":"1791472478547",'
    '"transaction_fee":{"network_fee":1000000000,"rpc_fee":1000000000,"additional_fee":0,"rpc_address":null},'
    '"data":["native",{"nativeOperation":"send","args":["706b89f5e2d56498a90bc3a209842b0bd0e22ce06bb4df7c27805e655614e5f1","9500000000"]}],'
    '"gcr_edits":[{"type":"balance","operation":"remove","isRollback":false,"account":"0xc0a58599ceaeba18f9c450133631cce4c45f4dc7a59c8026331504da3a913c2a","txhash":"","amount":"9500000000"},'
    '{"type":"balance","operation":"add","isRollback":false,"account":"0x706b89f5e2d56498a90bc3a209842b0bd0e22ce06bb4df7c27805e655614e5f1","txhash":"","amount":"9500000000"},'
    '{"type":"balance","account":"0xc0a58599ceaeba18f9c450133631cce4c45f4dc7a59c8026331504da3a913c2a","operation":"remove","amount":"1000000000","txhash":"","isRollback":false},'
    '{"type":"nonce","operation":"add","account":"0xc0a58599ceaeba18f9c450133631cce4c45f4dc7a59c8026331504da3a913c2a","amount":1,"txhash":"","isRollback":false}]},'
    '"signature":{"type":"ed25519","data":"0x259298fb483ea5849db23614ccf9f92cfa4d8dbfda59cb230b1ad2f36f8d9ce888668b80f4082eb04bff8a4820e22682f4fd9b019ad3c05f6c23b8cfc14bf70b"},'
    '"ed25519_signature":null,"hash":"85b8fcdcee48822742a39e1b9877f5e2f8dde36430e8e486e3a8b0c9a7744cbd",'
    '"status":"failed","blockNumber":480877,'
    '"attrs":{"code":"TX_NONCE_INVALID_LOW","message":"Invalid nonce edit. Expected 10, got 9","reference_block":480875}}'
)


def _apply(base: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    value = dict(base, **changes)
    return {key: item for key, item in value.items() if item is not _OMIT}


def retained(**changes: Any) -> dict[str, Any]:
    """DEM-1 retained transfer in the DEMOS-MAPPING §A.2 projected form."""
    return _apply(
        {
            "jobId": JOB_ID,
            "phaseIndex": PHASE_INDEX,
            "txHash": TX_HASH,
            "nonce": NONCE,
            "sender": PAYER_KEY,
            "recipient": PAYEE_KEY,
            "amountOs": AMOUNT_OS,
        },
        changes,
    )


def send_content(
    *,
    sender: str = PAYER_KEY,
    recipient: str = PAYEE_KEY,
    amount_os: str = AMOUNT_OS,
    nonce: Any = str(NONCE),
    amount: Any = None,
    **changes: Any,
) -> dict[str, Any]:
    """A native `send` body as the node serves it: `0x` parties, string
    nonce, numeric amount up to 2^53 - 1, unprefixed recipient argument."""
    if amount is None:
        amount = int(amount_os) if int(amount_os) <= 2**53 - 1 else amount_os
    return _apply(
        {
            "type": "native",
            "from": "0x" + sender,
            "from_ed25519_address": "0x" + sender,
            "to": "0x" + recipient,
            "amount": amount,
            "nonce": nonce,
            "data": ["native", {"nativeOperation": "send", "args": [recipient, amount_os]}],
        },
        changes,
    )


def record(status: str, content: dict[str, Any] | None = None, **changes: Any) -> dict[str, Any]:
    """A `getTxByHash` response record."""
    return _apply(
        {
            "hash": TX_HASH,
            "blockNumber": BLOCK,
            "status": status,
            "content": send_content() if content is None else content,
        },
        changes,
    )


def found(
    value: dict[str, Any], *, authenticated: bool | None = None, node: str = "pinned",
    applied: bool = True,
) -> dict[str, Any]:
    read: dict[str, Any] = {"state": "found", "nodeProfile": node, "record": value}
    if node == "unpinned":
        read["selfReportedCommit"] = "61b8e75aa8db5e408c49e1c3a89db4d673f45578"
    if authenticated is not None:
        read["authenticated"] = authenticated
    if applied:
        # Synthetic state-transition authority, separate from the RPC record.
        content = value["content"]
        read["appliedTransferAuthenticated"] = True
        read["appliedTransfer"] = {
            "txHash": value["hash"].removeprefix("0x").lower(), "blockNumber": int(value["blockNumber"]),
            "sender": content["from"].removeprefix("0x").lower(),
            "recipient": content["to"].removeprefix("0x").lower(),
            "payerDebitOs": str(int(content["amount"])), "payeeCreditOs": str(int(content["amount"])),
        }
    return read


NOT_FOUND = {"state": "not-found"}
UNAVAILABLE = {"state": "unavailable"}
INCLUDED_AT_BLOCK = {"blockNumber": BLOCK}


def handler_want(expected: str) -> dict[str, Any]:
    """PC-4 result and session consequence of one DEM-3/DEM-4/DEM-5 class."""
    executed, failed = expected == "pass", expected == "fail"
    return {
        "ok": executed,
        "errorClass": None if executed else ("permanent" if failed else "substrate"),
        "executionState": "executed" if executed else ("failed" if failed else "indeterminate"),
        "evidence": (
            "success-bft-final" if executed
            else "failure-without-settlement-finality" if failed else "none"
        ),
        "nextAction": (
            "anchor-success-evidence" if executed
            else "terminal-failure" if failed else "st7-pause-re-read-retained-hash"
        ),
        "onPauseExpiry": None if executed or failed else "failed-substrate-without-replacement",
        "retainedHashKept": True,
        "terminalFailureProofRetained": failed,
        # The payer's handler result never authorizes delivery or settlement
        # accounting; only the consumer's admit-for-delivery composition does.
        "deliveryAuthorized": False,
        "settlementAccounting": False,
        "broadcastPermitted": False,
        "replacementPermitted": False,
    }


def _vector(name, operation, protocol_input, expected, want, rule, guards, note):
    return {
        "name": name,
        "operation": operation,
        "protocolInput": protocol_input,
        "expected": expected,
        "want": want,
        "rule": "DACS-4 §9.5.9 " + rule,
        "guards": sorted(guards),
        "note": note,
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
    return _vector(
        name, "classify-execution",
        {
            "retainedTransfer": retained() if transfer is None else transfer,
            "statusIndex": status_index,
            "inclusionObservation": inclusion,
            "recordRead": read,
        },
        expected, handler_want(expected), rule, guards, note,
    )


def failure_proof(content: dict[str, Any] | None = None, **record_changes: Any) -> dict[str, Any]:
    return {
        "classification": "permanent",
        "inclusionBlock": BLOCK,
        "record": record(record_changes.pop("status", "failed"), content, **record_changes),
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
    return _vector(
        name, "resume-phase",
        {
            "retainedTransfer": retained(),
            "retainedFailureProof": proof,
            "statusIndex": status_index,
            "inclusionObservation": inclusion,
            "recordRead": read,
        },
        expected, handler_want(expected), rule, guards, note,
    )


def phase(**changes: Any) -> dict[str, Any]:
    """Authenticated agreement and phase context."""
    return _apply(
        {
            "jobId": JOB_ID,
            "phaseIndex": PHASE_INDEX,
            "payerPayingKey": PAYER_KEY,
            "payeeAddress": PAYEE_KEY,
            "amountOs": AMOUNT_OS,
            "amount": {"amount": "1.5", "currency": "DEM"},
        },
        changes,
    )


def content_hash(content: dict[str, Any]) -> str:
    """demosdk 4.0.16 `sign()`: SHA-256 hex of `JSON.stringify(content)`."""
    serialized = stringify(content)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def signed(
    content: dict[str, Any] | None = None,
    *,
    signer: Ed25519PrivateKey = PAYER_SIGNER,
    signed_content: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The signed native transaction as demosdk 4.0.16 builds it: numeric
    nonce, OS-string amount, `hash` over the serialized content and an
    Ed25519 signature over the UTF-8 hash. `signed_content` hashes and signs
    other content than the transaction carries (a forged hash)."""
    if content is None:
        content = send_content(nonce=NONCE, amount=AMOUNT_OS)
    content = copy.deepcopy(content)
    fees = {"network_fee": "1000000000", "rpc_fee": "1000000000", "additional_fee": "0", "rpc_address": None}
    content.setdefault("transaction_fee", fees)
    if signed_content is not None:
        signed_content = copy.deepcopy(signed_content)
        signed_content.setdefault("transaction_fee", fees)
    tx_hash = content_hash(content if signed_content is None else signed_content)
    return {
        "content": content,
        "hash": tx_hash,
        "signature": {"type": "ed25519", "data": "0x" + signer.sign(tx_hash.encode("utf-8")).hex()},
    }


# The hash of the default signed transfer, which every default record cites.
TX_HASH = signed()["hash"]


def gate(
    name: str,
    expected: str,
    rule: str,
    guards: list[str],
    note: str,
    *,
    transfer: dict[str, Any] | None = None,
    signed_transaction: dict[str, Any] | None = None,
    retained_elsewhere: list[dict[str, Any]] | None = None,
    durable: bool = True,
    broadcast_state: str = "never-broadcast",
    request: str = "broadcast-retained",
) -> dict[str, Any]:
    return _vector(
        name, "broadcast-gate",
        {
            "phase": phase(),
            "signedTransaction": signed() if signed_transaction is None else signed_transaction,
            "retainedTransfer": retained() if transfer is None else transfer,
            "hashRetainedForOtherPhases": retained_elsewhere or [],
            "retentionDurable": durable,
            "broadcastState": broadcast_state,
            "request": request,
        },
        expected, {"broadcastPermitted": expected == "pass"}, rule, guards, note,
    )


def consistent(
    content: dict[str, Any] | None = None,
    signer: Ed25519PrivateKey = PAYER_SIGNER,
    *,
    signed_content: dict[str, Any] | None = None,
    **retained_changes: Any,
) -> dict[str, Any]:
    """A signed transaction and a retention that cites its hash, so a gate
    vector differs from the control only in what it names."""
    transaction = signed(content, signer=signer, signed_content=signed_content)
    return {
        "signed_transaction": transaction,
        "transfer": retained(txHash=transaction["hash"], **retained_changes),
    }


def _admit_input(read: dict[str, Any], status_index: str) -> dict[str, Any]:
    return {
        "signedEvidence": {
            "outcome": "success",
            "txRef": {"kind": "demos", "txHash": TX_HASH, "blockNumber": BLOCK},
        },
        "phase": phase(),
        "statusIndex": status_index,
        "recordRead": read,
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
    signed_evidence: dict[str, Any] | None = None,
    phase_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    protocol_input = _admit_input(read, status_index)
    if signed_evidence is not None:
        protocol_input["signedEvidence"] = signed_evidence
    if phase_context is not None:
        protocol_input["phase"] = phase_context
    # DEM-7 alone is one gate: it never authorizes delivery by itself.
    return _vector(
        name, "admit-evidence", protocol_input, expected,
        {"dem7GatePassed": expected == "pass", "deliveryAuthorized": False},
        rule, guards, note,
    )


ALL_GATES_PASS = {"fv": "pass", "sb1": "pass", "pb": "pass"}


def deliver(
    name: str,
    expected: str,
    rule: str,
    guards: list[str],
    note: str,
    *,
    read: dict[str, Any] | None = None,
    gates: dict[str, str] | None = None,
    admissions: list[dict[str, Any]] | None = None,
    dem7_passed: bool = True,
) -> dict[str, Any]:
    protocol_input = _admit_input(
        found(record("confirmed"), authenticated=True) if read is None else read, "included"
    )
    protocol_input["otherGates"] = _apply(ALL_GATES_PASS, gates or {})
    protocol_input["consumerAdmissions"] = [
        dict(admission, txRef={"kind": "demos", "txHash": TX_HASH, "blockNumber": BLOCK})
        for admission in (admissions or [])
    ]
    return _vector(
        name, "admit-for-delivery", protocol_input, expected,
        {
            "dem7GatePassed": dem7_passed,
            "deliveryAuthorized": expected == "pass",
            "settlementAccounting": expected == "pass",
        },
        rule, guards, note,
    )


def _live(value: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    content = value["content"]
    transfer = retained(
        txHash=value["hash"],
        nonce=int(content["nonce"]),
        sender=content["from"][2:],
        recipient=content["to"][2:],
        amountOs=str(content["amount"]),
    )
    return transfer, {"blockNumber": value["blockNumber"]}


def build_vectors() -> list[dict[str, Any]]:
    unbound = "DEM-2/DEM-5"
    unresolved = ["success-requires-record", "unresolved-authorizes-nothing"]
    live_confirmed, live_confirmed_block = _live(NODE2_CONFIRMED)
    live_failed, live_failed_block = _live(NODE2_FAILED)
    payload = send_content()
    vectors = [
        # Handler classification: the bound record decides, never the index.
        classify(
            "included-confirmed", "pass", "DEM-3", ["success-authorizes-no-delivery", "success-branch"],
            "A bound confirmed record in the node's wire form is the only success.",
            read=found(record("confirmed")),
        ),
        classify(
            "node2-confirmed-record", "indeterminate", "DEM-2/DEM-3", ["success-requires-applied-transfer"] + unresolved,
            "The live confirmed RPC record has no independent applied-transfer authority.",
            read=found(copy.deepcopy(NODE2_CONFIRMED), applied=False), transfer=live_confirmed, inclusion=live_confirmed_block,
        ),
        classify(
            "confirmed-integer-nonce-binds", "pass", "DEM-2/DEM-3", ["success-authorizes-no-delivery", "success-branch"],
            "A safe JSON integer nonce projects to the same signed nonce.",
            read=found(record("confirmed", send_content(nonce=NONCE))),
        ),
        classify(
            "confirmed-large-string-amount-binds", "pass", "DEM-2/DEM-3", ["success-authorizes-no-delivery", "success-branch"],
            "Above 2^53 - 1 OS the node serves the amount as a decimal string; it binds by integer value.",
            read=found(record("confirmed", send_content(amount_os=LARGE_AMOUNT_OS))),
            transfer=retained(amountOs=LARGE_AMOUNT_OS),
        ),
        classify(
            "confirmed-unprefixed-parties-bind", "pass", "DEM-2/DEM-3", ["success-authorizes-no-delivery", "success-branch"],
            "A party key without the 0x prefix projects to the same DACS-1 key.",
            read=found(record("confirmed", send_content(**{"from": PAYER_KEY, "from_ed25519_address": PAYER_KEY, "to": PAYEE_KEY}))),
        ),
        classify(
            "included-failed", "fail", "DEM-4/DEM-6", ["failure-is-permanent", "failure-proof-retained", "no-replacement", "success-requires-record"],
            "Included is not executed: a bound failed record is a durable permanent failure with no replacement.",
            read=found(record("failed")),
        ),
        classify(
            "node2-included-failed-record", "fail", "DEM-2/DEM-4", ["failure-is-permanent", "failure-proof-retained", "no-replacement", "success-requires-record"],
            "A live node2 transfer whose status index said included while its record failed (TX_NONCE_INVALID_LOW).",
            read=found(copy.deepcopy(NODE2_FAILED)), transfer=live_failed, inclusion=live_failed_block,
        ),
        classify(
            "included-pending", "indeterminate", "DEM-5", unresolved,
            "Included with a pending record is unresolved: substrate, re-read only.",
            read=found(record("pending")),
        ),
        classify(
            "included-record-not-found", "indeterminate", "DEM-5/DEM-6", ["no-rebroadcast"] + unresolved,
            "Included but no record for the retained hash: execution is unknown and nothing is resent.",
            read=NOT_FOUND,
        ),
        classify(
            "included-record-unavailable", "indeterminate", "DEM-5", unresolved,
            "An unreachable node leaves execution unknown; no success, failure or delivery.",
            read=UNAVAILABLE,
        ),
        classify(
            "included-alias", "indeterminate", "DEM-3", ["success-requires-exact-confirmed"] + unresolved,
            "A record status copied from the index label is not an execution result.",
            read=found(record("included")),
        ),
        classify(
            "finalized-alias", "indeterminate", "DEM-3", ["success-requires-exact-confirmed"] + unresolved,
            "Finality vocabulary is not the executed record status.",
            read=found(record("finalized")),
        ),
        classify(
            "success-alias", "indeterminate", "DEM-3", ["success-requires-exact-confirmed"] + unresolved,
            "Only the exact Demos record status confirmed establishes execution.",
            read=found(record("success")),
        ),
        classify(
            "confirmed-case-variant", "indeterminate", "DEM-3", ["success-requires-exact-confirmed"] + unresolved,
            "Status comparison is exact; a case variant is unknown.",
            read=found(record("Confirmed")),
        ),
        classify(
            "confirmed-unpinned-node", "indeterminate", unbound, ["node-profile-pinned"] + unresolved,
            "A node not pinned to the profile's execution-record semantics may store a failed transfer as confirmed.",
            read=found(record("confirmed"), node="unpinned"),
        ),
        classify(
            "failed-unpinned-node", "indeterminate", unbound, ["failure-requires-binding", "node-profile-pinned"] + unresolved,
            "A failed record from an unpinned node proves nothing about execution either.",
            read=found(record("failed"), node="unpinned"),
        ),
        classify(
            "confirmed-wrong-hash", "indeterminate", unbound, ["bind-hash"] + unresolved,
            "A confirmed record for another hash says nothing about the retained transfer.",
            read=found(record("confirmed", hash=OTHER_TX_HASH)),
        ),
        classify(
            "confirmed-wrong-nonce", "indeterminate", unbound, ["bind-nonce"] + unresolved,
            "A record whose nonce differs from the signed nonce is unbound.",
            read=found(record("confirmed", send_content(nonce=str(NONCE + 1)))),
        ),
        classify(
            "confirmed-wrong-block", "indeterminate", unbound, ["bind-block"] + unresolved,
            "A record in a different block from the inclusion observation is unbound.",
            read=found(record("confirmed", blockNumber=BLOCK + 1)),
        ),
        classify(
            "confirmed-wrong-sender", "indeterminate", unbound, ["bind-sender"] + unresolved,
            "A record debiting another sender is unbound.",
            read=found(record("confirmed", send_content(sender=OTHER_KEY))),
        ),
        classify(
            "confirmed-wrong-recipient", "indeterminate", unbound, ["bind-recipient"] + unresolved,
            "A record paying another recipient is unbound.",
            read=found(record("confirmed", send_content(recipient=OTHER_KEY))),
        ),
        classify(
            "confirmed-wrong-amount", "indeterminate", unbound, ["bind-amount"] + unresolved,
            "A record for a different OS amount is unbound.",
            read=found(record("confirmed", send_content(amount_os=OTHER_AMOUNT_OS))),
        ),
        classify(
            "confirmed-missing-nonce", "indeterminate", unbound, ["decode-nonce"] + unresolved,
            "A record missing its nonce does not decode.",
            read=found(record("confirmed", send_content(nonce=_OMIT))),
        ),
        classify(
            "confirmed-boolean-nonce", "indeterminate", unbound, ["decode-nonce"] + unresolved,
            "true is not a nonce, even when the signed nonce is 1.",
            read=found(record("confirmed", send_content(nonce=True))),
            transfer=retained(nonce=1),
        ),
        classify(
            "confirmed-fractional-nonce", "indeterminate", unbound, ["decode-nonce"] + unresolved,
            "A non-integer number does not decode as a nonce.",
            read=found(record("confirmed", send_content(nonce=NONCE + 0.5))),
        ),
        classify(
            "confirmed-leading-zero-nonce", "indeterminate", unbound, ["decode-nonce"] + unresolved,
            "A decimal string with a leading zero is not canonical.",
            read=found(record("confirmed", send_content(nonce="0" + str(NONCE)))),
        ),
        classify(
            "confirmed-fractional-amount", "indeterminate", unbound, ["decode-amount"] + unresolved,
            "A non-integer amount is not an OS amount.",
            read=found(record("confirmed", send_content(amount=int(AMOUNT_OS) + 0.5))),
        ),
        classify(
            "confirmed-noncanonical-amount", "indeterminate", unbound, ["decode-amount"] + unresolved,
            "A decimal amount string with a leading zero is not canonical.",
            read=found(record("confirmed", send_content(amount="0" + AMOUNT_OS))),
        ),
        classify(
            "confirmed-prefixed-hash", "indeterminate", unbound, ["decode-hash"] + unresolved,
            "The Demos hash is 64 lowercase hex digits without 0x.",
            read=found(record("confirmed", hash="0x" + TX_HASH)),
        ),
        classify(
            "confirmed-uppercase-sender", "indeterminate", unbound, ["decode-address"] + unresolved,
            "A party key with uppercase hex does not decode.",
            read=found(record("confirmed", send_content(**{"from": "0x" + PAYER_KEY.upper(), "from_ed25519_address": "0x" + PAYER_KEY.upper()}))),
        ),
        classify(
            "confirmed-sender-alias-mismatch", "indeterminate", unbound, ["decode-address"] + unresolved,
            "from and from_ed25519_address must name the same key.",
            read=found(record("confirmed", send_content(from_ed25519_address="0x" + OTHER_KEY))),
        ),
        classify(
            "confirmed-payload-recipient-mismatch", "indeterminate", unbound, ["decode-native-send"] + unresolved,
            "The native send argument must credit the same recipient as content.to.",
            read=found(record("confirmed", send_content(data=["native", {"nativeOperation": "send", "args": [OTHER_KEY, AMOUNT_OS]}]))),
        ),
        classify(
            "confirmed-payload-amount-mismatch", "indeterminate", unbound, ["decode-native-send"] + unresolved,
            "The native send argument must carry the same OS amount as content.amount.",
            read=found(record("confirmed", send_content(data=["native", {"nativeOperation": "send", "args": [PAYEE_KEY, OTHER_AMOUNT_OS]}]))),
        ),
        classify(
            "confirmed-not-native-send", "indeterminate", unbound, ["decode-native-send"] + unresolved,
            "Only a native send moves the payment.",
            read=found(record("confirmed", _apply(payload, {"data": ["native", {"nativeOperation": "burn", "args": [PAYEE_KEY, AMOUNT_OS]}]}))),
        ),
        classify(
            "confirmed-without-inclusion-observation", "indeterminate", unbound, ["bind-block", "bind-requires-inclusion"],
            "Without an inclusion observation the record's block cannot be bound.",
            read=found(record("confirmed")), status_index="pending", inclusion=None,
        ),
        classify(
            "failed-wrong-nonce", "indeterminate", unbound, ["bind-nonce", "failure-requires-binding"] + unresolved,
            "A failed record with another nonce does not prove this transfer failed.",
            read=found(record("failed", send_content(nonce=str(NONCE + 1)))),
        ),
        classify(
            "failed-missing-nonce", "indeterminate", unbound, ["decode-nonce"] + unresolved,
            "A failed record missing its nonce does not decode, so it proves nothing.",
            read=found(record("failed", send_content(nonce=_OMIT))),
        ),
        classify(
            "failed-wrong-block", "indeterminate", unbound, ["bind-block", "failure-requires-binding"] + unresolved,
            "A failed record in another block conflicts with the inclusion observation.",
            read=found(record("failed", blockNumber=BLOCK + 1)),
        ),
        classify(
            "failed-wrong-amount", "indeterminate", unbound, ["bind-amount", "failure-requires-binding"] + unresolved,
            "A failed record for another amount does not prove this transfer failed.",
            read=found(record("failed", send_content(amount_os=OTHER_AMOUNT_OS))),
        ),
        classify(
            "failed-wrong-hash", "indeterminate", unbound, ["bind-hash", "failure-requires-binding"] + unresolved,
            "A failed record for another hash does not prove this transfer failed.",
            read=found(record("failed", hash=OTHER_TX_HASH)),
        ),
        classify(
            "failed-wrong-sender", "indeterminate", unbound, ["bind-sender", "failure-requires-binding"] + unresolved,
            "A failed record from another sender does not prove this transfer failed.",
            read=found(record("failed", send_content(sender=OTHER_KEY))),
        ),
        classify(
            "failed-wrong-recipient", "indeterminate", unbound, ["bind-recipient", "failure-requires-binding"] + unresolved,
            "A failed record to another recipient does not prove this transfer failed.",
            read=found(record("failed", send_content(recipient=OTHER_KEY))),
        ),
        classify(
            "failed-without-inclusion-observation", "indeterminate", unbound, ["bind-block", "bind-requires-inclusion", "failure-requires-binding"],
            "A failed record without an inclusion observation is not a bound failure.",
            read=found(record("failed")), status_index="unknown", inclusion=None,
        ),
        classify(
            "transfer-unknown-not-rebroadcast", "indeterminate", "DEM-6", ["no-rebroadcast"],
            "The node's status index says unknown and there is no record; the handler still only re-reads.",
            read=NOT_FOUND, status_index="unknown", inclusion=None,
        ),
        # Recovery and resume.
        resume(
            "resume-reuses-failure-proof", "fail", "DEM-4/DEM-6", ["failure-proof-retained", "no-replacement", "resume-reuses-failure-proof"],
            "A resume after a proven failure reuses it even while the node is unreachable.",
            proof=failure_proof(), read=UNAVAILABLE,
        ),
        resume(
            "resume-corrupted-failure-proof", "indeterminate", "DEM-4/DEM-6", ["bind-nonce", "no-rebroadcast", "resume-validates-failure-proof"] + unresolved,
            "A retained proof whose nonce no longer binds is not reused; re-read only.",
            proof=failure_proof(send_content(nonce=str(NONCE + 1))), read=NOT_FOUND,
        ),
        resume(
            "resume-corrupted-failure-proof-recipient", "indeterminate", "DEM-4/DEM-6", ["bind-recipient", "no-rebroadcast", "resume-validates-failure-proof"] + unresolved,
            "A retained proof for another recipient is not reused.",
            proof=failure_proof(send_content(recipient=OTHER_KEY)), read=NOT_FOUND,
        ),
        resume(
            "resume-corrupted-failure-proof-block", "indeterminate", "DEM-4/DEM-6", ["bind-block", "no-rebroadcast", "resume-validates-failure-proof"] + unresolved,
            "A retained proof whose record is in another block than its inclusion block is not reused.",
            proof=failure_proof(blockNumber=BLOCK + 1), read=NOT_FOUND,
        ),
        resume(
            "resume-corrupted-failure-proof-status", "indeterminate", "DEM-4/DEM-6", ["no-rebroadcast", "resume-validates-failure-proof"] + unresolved,
            "A retained proof whose record is not failed is not a failure proof.",
            proof=failure_proof(status="pending"), read=NOT_FOUND,
        ),
        resume(
            "resume-without-proof-not-found", "indeterminate", "DEM-6", ["no-rebroadcast"],
            "A crash after a possible broadcast resumes by re-reading, never resending.",
            proof=None, read=NOT_FOUND, status_index="unknown", inclusion=None,
        ),
        resume(
            "resume-without-proof-confirmed", "pass", "DEM-3/DEM-6", ["success-authorizes-no-delivery", "success-branch"],
            "Re-reading the retained hash finds the executed transfer; no second payment.",
            proof=None, read=found(record("confirmed")),
        ),
        # First-broadcast gate.
        gate(
            "first-broadcast-after-durable-retention", "pass", "DEM-1", ["first-broadcast-allowed"],
            "The single broadcast is allowed once the signed transfer is durably retained for this phase.",
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
            "broadcast-with-retention-missing-recipient", "error", "DEM-1", ["broadcast-requires-complete-retention"],
            "A retained transfer without its recipient is structurally incomplete.",
            transfer=retained(recipient=_OMIT),
        ),
        gate(
            "broadcast-with-retention-missing-phase", "error", "DEM-1", ["broadcast-requires-complete-retention"],
            "A retained transfer not keyed to a phase index is structurally incomplete.",
            transfer=retained(phaseIndex=_OMIT),
        ),
        gate(
            "broadcast-with-ill-typed-retained-amount", "error", "DEM-1", ["broadcast-requires-complete-retention"],
            "The retained OS amount is a canonical decimal string.",
            transfer=retained(amountOs=int(AMOUNT_OS)),
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
        gate(
            "broadcast-retained-for-another-job", "fail", "DEM-1", ["retention-bound-to-phase"],
            "A transfer retained for another job cannot pay this phase.",
            transfer=retained(jobId=OTHER_JOB_ID),
        ),
        gate(
            "broadcast-retained-for-another-phase", "fail", "DEM-1", ["retention-bound-to-phase"],
            "A transfer retained for another phase index of the same job cannot pay this phase.",
            transfer=retained(phaseIndex=PHASE_INDEX + 1),
        ),
        gate(
            "broadcast-from-another-paying-key", "fail", "DEM-1", ["retained-sender-is-payer"],
            "A transfer signed by a key other than payer.payingKey is refused, even when retained consistently.",
            **consistent(send_content(sender=OTHER_KEY, nonce=NONCE, amount=AMOUNT_OS), OTHER_SIGNER, sender=OTHER_KEY),
        ),
        gate(
            "broadcast-to-another-destination", "fail", "DEM-1", ["retained-recipient-is-payee"],
            "A transfer to a destination other than payee.payeeAddress is refused, even when retained consistently.",
            **consistent(send_content(recipient=OTHER_KEY, nonce=NONCE, amount=AMOUNT_OS), recipient=OTHER_KEY),
        ),
        gate(
            "broadcast-of-another-amount", "fail", "DEM-1", ["retained-amount-is-phase-amount"],
            "A transfer of an amount other than the phase amount in OS is refused.",
            **consistent(send_content(amount_os=OTHER_AMOUNT_OS, nonce=NONCE, amount=OTHER_AMOUNT_OS), amountOs=OTHER_AMOUNT_OS),
        ),
        gate(
            "broadcast-signed-nonce-differs", "fail", "DEM-1", ["signed-transfer-matches-retention"],
            "The retained nonce must be the nonce the payer signed.",
            **consistent(send_content(nonce=NONCE + 1, amount=AMOUNT_OS)),
        ),
        gate(
            "broadcast-signed-sender-differs", "fail", "DEM-1", ["signed-transfer-matches-retention"],
            "An authentic transfer from another key must not replace the retained payer transfer.",
            **consistent(send_content(sender=OTHER_KEY, nonce=NONCE, amount=AMOUNT_OS), OTHER_SIGNER),
        ),
        gate(
            "broadcast-signed-recipient-differs", "fail", "DEM-1", ["signed-transfer-matches-retention"],
            "Signed bytes that pay another destination than the retained recipient are refused.",
            **consistent(send_content(recipient=OTHER_KEY, nonce=NONCE, amount=AMOUNT_OS)),
        ),
        gate(
            "broadcast-signed-amount-differs", "fail", "DEM-1", ["signed-transfer-matches-retention"],
            "Signed bytes for another amount than the retained OS amount are refused.",
            **consistent(send_content(amount_os=OTHER_AMOUNT_OS, nonce=NONCE, amount=OTHER_AMOUNT_OS)),
        ),
        gate(
            "broadcast-signed-hash-differs", "fail", "DEM-1", ["signed-transfer-matches-retention"],
            "The retained hash must be the hash of the signed transaction.",
            transfer=retained(txHash=OTHER_TX_HASH),
        ),
        gate(
            "broadcast-signed-pre-fork-amount", "fail", "DEM-1", ["decode-native-send", "signed-transfer-matches-retention"],
            "A send signed in the pre-osDenomination form (numeric amount argument) does not decode, so it is never broadcast.",
            **consistent(send_content(nonce=NONCE, amount=AMOUNT_OS, data=["native", {"nativeOperation": "send", "args": [PAYEE_KEY, int(AMOUNT_OS)]}])),
        ),
        gate(
            "broadcast-signed-uppercase-recipient", "fail", "DEM-1", ["decode-address", "signed-transfer-matches-retention"],
            "demosdk accepts an upper-case recipient, but it does not decode under the profile, so it is never broadcast.",
            **consistent(send_content(nonce=NONCE, amount=AMOUNT_OS, to="0x" + PAYEE_KEY.upper(), data=["native", {"nativeOperation": "send", "args": [PAYEE_KEY.upper(), AMOUNT_OS]}])),
        ),
        gate(
            "broadcast-unsigned-transaction", "fail", "DEM-1", ["signed-transaction-authentic"],
            "A claimed transaction without the payer's signature is not a signed transfer.",
            signed_transaction=_apply(signed(), {"signature": _OMIT}),
        ),
        gate(
            "broadcast-hash-not-over-content", "fail", "DEM-1", ["signed-transaction-authentic"],
            "A hash and signature made over other content (here another nonce) do not commit to the content retained.",
            **consistent(signed_content=send_content(nonce=NONCE + 1, amount=AMOUNT_OS)),
        ),
        gate(
            "broadcast-signed-by-another-key", "fail", "DEM-1", ["signed-transaction-authentic"],
            "A signature by a key other than content.from does not authenticate the payer's transfer.",
            **consistent(signer=OTHER_SIGNER),
        ),
        gate(
            "broadcast-signature-type-not-ed25519", "fail", "DEM-1", ["signed-transaction-authentic"],
            "Only an ed25519 signature by the sender key is verified under the profile.",
            signed_transaction=_apply(signed(), {"signature": {"type": "falcon", "data": signed()["signature"]["data"]}}),
        ),
        gate(
            "broadcast-hash-retained-for-another-phase", "fail", "DEM-1/DEM-6", ["no-cross-phase-reuse"],
            "One signed transfer cannot be retained for, and pay, two phases.",
            retained_elsewhere=[{"jobId": OTHER_JOB_ID, "phaseIndex": PHASE_INDEX}],
        ),
        # Consumer DEM-7 gate, including the payee before delivery.
        admit(
            "consumer-confirmed-gate-passes", "pass", "DEM-7", ["consumer-admits-confirmed"],
            "A bound confirmed record passes DEM-7 only; it authorizes no delivery by itself.",
            read=found(record("confirmed")),
        ),
        admit(
            "consumer-node2-confirmed-refused", "indeterminate", "DEM-7", ["success-requires-applied-transfer", "consumer-requires-confirmed-record"],
            "The live confirmed record cannot replace independently authenticated applied payment authority.",
            read=found(copy.deepcopy(NODE2_CONFIRMED), applied=False),
            signed_evidence={
                "outcome": "success",
                "txRef": {"kind": "demos", "txHash": NODE2_CONFIRMED["hash"], "blockNumber": NODE2_CONFIRMED["blockNumber"]},
            },
            phase_context=phase(
                payerPayingKey=live_confirmed["sender"],
                payeeAddress=live_confirmed["recipient"],
                amountOs=live_confirmed["amountOs"],
            ),
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
            "consumer-success-alias-refused", "indeterminate", "DEM-7", ["consumer-requires-confirmed-record", "success-requires-exact-confirmed"],
            "The fixture-codec word success is not a Demos record status.",
            read=found(record("success")),
        ),
        admit(
            "consumer-case-variant-refused", "indeterminate", "DEM-7", ["consumer-requires-confirmed-record", "success-requires-exact-confirmed"],
            "Status comparison is exact for consumers too.",
            read=found(record("CONFIRMED")),
        ),
        admit(
            "consumer-unpinned-node-refused", "indeterminate", "DEM-7", ["consumer-requires-confirmed-record", "node-profile-pinned"],
            "A confirmed record from a node without the pinned execution-record semantics is not admitted.",
            read=found(record("confirmed"), node="unpinned"),
        ),
        admit(
            "consumer-failed-fails", "fail", "DEM-7", ["consumer-failed-refutes", "consumer-requires-confirmed-record"],
            "A bound failed record refutes the success evidence.",
            read=found(record("failed")),
        ),
        admit(
            "consumer-wrong-payee-unauthenticated", "indeterminate", "DEM-7", ["consumer-binding", "consumer-requires-confirmed-record"],
            "An unauthenticated read that pays another payee does not satisfy DEM-7.",
            read=found(record("confirmed", send_content(recipient=OTHER_KEY)), authenticated=False),
        ),
        admit(
            "consumer-wrong-block-unauthenticated", "indeterminate", "DEM-7", ["consumer-binding", "consumer-requires-confirmed-record"],
            "An unauthenticated read in another block does not satisfy DEM-7.",
            read=found(record("confirmed", blockNumber=BLOCK + 1), authenticated=False),
        ),
        admit(
            "consumer-wrong-payer-unauthenticated", "indeterminate", "DEM-7", ["consumer-binding", "consumer-requires-confirmed-record"],
            "An unauthenticated read from another payer does not satisfy DEM-7.",
            read=found(record("confirmed", send_content(sender=OTHER_KEY)), authenticated=False),
        ),
        admit(
            "consumer-wrong-amount-authenticated", "fail", "DEM-7/FV-5", ["consumer-authenticated-contradiction-fails", "consumer-binding", "consumer-requires-confirmed-record"],
            "Under FV-5 an authenticated record for another amount is fail.",
            read=found(record("confirmed", send_content(amount_os=OTHER_AMOUNT_OS)), authenticated=True),
        ),
        admit(
            "consumer-wrong-payee-authenticated", "fail", "DEM-7/FV-5", ["consumer-authenticated-contradiction-fails", "consumer-binding", "consumer-requires-confirmed-record"],
            "Under FV-5 an authenticated record paying another payee is fail.",
            read=found(record("confirmed", send_content(recipient=OTHER_KEY)), authenticated=True),
        ),
        # Delivery: DEM-7 composed with FV-5 authentication, SB and PB.
        deliver(
            "delivery-after-all-gates", "pass", "DEM-7/FV-5", ["consumer-admits-confirmed"],
            "A bound confirmed record, FV-5-authenticated, with SB-1, SB-2 and PB passing, authorizes delivery.",
        ),
        deliver(
            "delivery-record-unauthenticated", "indeterminate", "DEM-7/FV-5", ["consumer-admits-confirmed", "delivery-requires-authenticated-record"],
            "A bound confirmed record from a plain RPC read is not BFT-final proof; no delivery.",
            read=found(record("confirmed")),
        ),
        deliver(
            "delivery-dem7-pending", "indeterminate", "DEM-7", ["consumer-requires-confirmed-record", "delivery-requires-dem7"],
            "FV, SB and PB passing do not replace an executed record.",
            read=found(record("pending"), authenticated=True), dem7_passed=False,
        ),
        deliver(
            "delivery-fv-indeterminate", "indeterminate", "DEM-7/FV-5", ["consumer-admits-confirmed", "delivery-requires-fv"],
            "Without verified BFT finality the confirmed record authorizes nothing.",
            gates={"fv": "indeterminate"},
        ),
        deliver(
            "delivery-sb1-fails", "fail", "DEM-7/SB-1", ["consumer-admits-confirmed", "delivery-requires-sb1"],
            "A confirmed transfer cited under another anchor tuple is rejected by SB-1.",
            gates={"sb1": "fail"},
        ),
        deliver(
            "delivery-pb-fails", "fail", "DEM-7/PB-1", ["consumer-admits-confirmed", "delivery-requires-pb"],
            "A confirmed transfer to a destination outside the agreement is rejected by PB.",
            gates={"pb": "fail"},
        ),
        deliver(
            "delivery-hash-admitted-for-another-job", "indeterminate", "DEM-7/SB-2", ["consumer-admits-confirmed", "delivery-sb2-own-admissions"],
            "pay-dem has no settlement-side job binding: a demos:{txHash} the payee already admitted for another job makes the group indeterminate.",
            admissions=[{"jobId": OTHER_JOB_ID, "phaseIndex": PHASE_INDEX}],
        ),
        deliver(
            "delivery-hash-admitted-for-another-phase", "indeterminate", "DEM-7/SB-2", ["consumer-admits-confirmed", "delivery-sb2-own-admissions"],
            "The same collision rule applies to another phase index of the same job.",
            admissions=[{"jobId": JOB_ID, "phaseIndex": PHASE_INDEX + 1}],
        ),
        deliver(
            "delivery-same-tuple-readmitted", "pass", "DEM-7/SB-2", ["consumer-admits-confirmed", "sb2-same-tuple-idempotent"],
            "Re-presenting the same evidence for the same tuple is idempotent.",
            admissions=[{"jobId": JOB_ID, "phaseIndex": PHASE_INDEX}],
        ),
    ]
    for name, content, guard in (
        ("non-native-type", send_content(type="escrow"), "decode-type"),
        ("uppercase-recipient", send_content(to="0x" + PAYEE_KEY.upper()), "decode-address"),
        ("uppercase-send-argument", send_content(data=["native", {"nativeOperation": "send", "args": [PAYEE_KEY.upper(), AMOUNT_OS]}]), "decode-address"),
        ("non-native-tag", send_content(data=["escrow", payload["data"][1]]), "decode-native-send"),
        ("extra-send-member", send_content(data=["native", dict(payload["data"][1], extra=True)]), "decode-native-send"),
        ("extra-send-argument", send_content(data=["native", {"nativeOperation": "send", "args": [PAYEE_KEY, AMOUNT_OS, "extra"]}]), "decode-native-send"),
    ):
        guards = [guard] + (["decode-native-send"] if name == "uppercase-send-argument" else [])
        vectors.append(classify("confirmed-" + name, "indeterminate", unbound, guards + unresolved,
                                "Every native-send profile member is checked exactly.", read=found(record("confirmed", content))))
    vectors.append(admit("consumer-non-native-type-refused", "indeterminate", "DEM-7",
                         ["decode-type", "consumer-requires-confirmed-record"], "A non-native type never settles.",
                         read=found(record("confirmed", send_content(type="escrow")))))
    vectors.append(gate("broadcast-signed-non-native-type", "fail", "DEM-1",
                        ["decode-type", "signed-transfer-matches-retention"], "A send-shaped escrow transaction is not a native transfer.",
                        **consistent(send_content(nonce=NONCE, amount=AMOUNT_OS, type="escrow"))))
    vectors.append(gate("broadcast-signed-numeric-os-amount", "fail", "DEM-1",
                        ["signed-os-strings", "signed-transfer-matches-retention"],
                        "Post-fork signed amounts use canonical OS strings, never DEM-interpreted JSON numbers.",
                        **consistent(send_content(nonce=NONCE, amount=int(AMOUNT_OS)))))
    vectors.append(gate("broadcast-signed-numeric-os-fee", "fail", "DEM-1",
                        ["signed-os-strings", "signed-transfer-matches-retention"],
                        "Post-fork signed fee amounts use canonical OS strings.",
                        **consistent(send_content(nonce=NONCE, amount=AMOUNT_OS, transaction_fee={
                            "network_fee": 1_000_000_000, "rpc_fee": "1000000000", "additional_fee": "0", "rpc_address": None}))))
    vectors.append(gate("broadcast-dem-os-misconversion", "fail", "DEM-1",
                        ["retained-amount-is-phase-amount"], "1.5 DEM is 1500000000 OS, not 1500000001.",
                        **consistent(send_content(nonce=NONCE, amount=OTHER_AMOUNT_OS, amount_os=OTHER_AMOUNT_OS), amountOs=OTHER_AMOUNT_OS)))
    vectors.append(classify("confirmed-string-block-number", "indeterminate", unbound,
                            ["decode-block"] + unresolved, "blockNumber must be a JSON number, never a string.",
                            read=found(record("confirmed", blockNumber=str(BLOCK)))))
    for suffix, changes in (("missing", {}), ("empty", {"gcr_edits": []}), ("malformed", {"gcr_edits": {}})):
        read = found(record("confirmed", send_content(**changes)), applied=False)
        vectors.append(classify("confirmed-unproven-" + suffix + "-edits", "indeterminate", "DEM-3/DEM-5",
                                ["success-requires-applied-transfer"] + unresolved,
                                "Confirmed is not proof of a committed payment state transition.", read=read))
        vectors.append(admit("consumer-unproven-" + suffix + "-edits", "indeterminate", "DEM-7",
                             ["consumer-requires-confirmed-record", "success-requires-applied-transfer"],
                             "No applied payee credit authority means no settlement.", read=read))
    vectors.append(deliver("delivery-confirmed-without-applied-payment", "indeterminate", "DEM-7/FV-5",
                           ["consumer-requires-confirmed-record", "delivery-requires-dem7", "success-requires-applied-transfer"],
                           "All other gates passing cannot authorize delivery without proof of applied payment.",
                           read=found(record("confirmed", send_content(gcr_edits=[])), authenticated=True, applied=False),
                           dem7_passed=False))
    for suffix, changes in (
        ("unauthenticated", {"appliedTransferAuthenticated": False}),
        ("zero-credit", {"payeeCreditOs": "0"}),
        ("zero-debit", {"payerDebitOs": "0"}),
        ("wrong-hash", {"txHash": OTHER_TX_HASH}),
        ("wrong-block", {"blockNumber": BLOCK + 1}),
        ("wrong-sender", {"sender": OTHER_KEY}),
        ("wrong-recipient", {"recipient": OTHER_KEY}),
    ):
        read = found(record("confirmed"))
        if suffix == "unauthenticated":
            read.update(changes)
        else:
            read["appliedTransfer"].update(changes)
        vectors.append(classify("confirmed-applied-transfer-" + suffix, "indeterminate", "DEM-3/DEM-5",
                                ["success-requires-applied-transfer"] + unresolved,
                                "Applied payment authority must authenticate this exact native send.", read=read))
        vectors.append(admit("consumer-applied-transfer-" + suffix,
                             "indeterminate" if suffix == "unauthenticated" else "fail", "DEM-7/FV-5",
                             ["consumer-requires-confirmed-record", "success-requires-applied-transfer"]
                             + ([] if suffix == "unauthenticated" else ["consumer-authenticated-contradiction-fails"]),
                             "Authenticated applied-payment contradictions refute settlement; unavailable authority is indeterminate.", read=read))

    ref = {"kind": "demos", "txHash": TX_HASH, "blockNumber": BLOCK}
    for name, value, legacy, expected in (
        ("canonical", TX_HASH, False, "pass"),
        ("legacy-spelling", "0x" + TX_HASH.upper(), True, "pass"),
        ("current-prefixed", "0x" + TX_HASH, False, "error"),
        ("current-uppercase", TX_HASH.upper(), False, "error"),
        ("malformed", "gg" * 32, False, "error"),
        ("short", TX_HASH[:-1], False, "error"),
    ):
        vectors.append(_vector("sb1-demos-" + name, "project-settlement-id",
                               {"txRef": dict(ref, txHash=value), "legacy": legacy}, expected,
                               {"settlementTxId": "demos:" + TX_HASH if expected == "pass" else None},
                               "DEM-7/SB-1", [], "Project a verified raw Demos ChainTxRef to the byte-identical settlement ID."))
    for name, second_ref, expected in (
        ("two-job-collision", dict(ref, blockNumber=BLOCK + 1), "indeterminate"),
        ("distinct-hash-control", dict(ref, txHash=OTHER_TX_HASH), "pass"),
    ):
        refs = [ref, second_ref]
        vectors.append(_vector("sb2-demos-" + name, "resolve-settlement-group",
                               {"records": [{"jobId": job, "phaseIndex": PHASE_INDEX, "txRef": item}
                                            for job, item in zip((JOB_ID, OTHER_JOB_ID), refs)]}, expected,
                               {"records": [{"settlementTxId": "demos:" + item["txHash"], "decision": expected} for item in refs]},
                               "DEM-7/SB-1/SB-2", [], "Derive keys before grouping; no job or block coordinate may split one transfer."))
    for vector in vectors:
        if vector["operation"] == "project-settlement-id":
            name = vector["name"]
            vector["guards"] = (
                ["sb1-demos-id"] if name.endswith("-canonical") else
                ["sb1-demos-id", "sb1-demos-shape"] if name.endswith("-legacy-spelling") else
                ["sb1-demos-canonical", "sb1-demos-shape"] if name.endswith(("-current-prefixed", "-current-uppercase")) else
                ["sb1-demos-shape"]
            )
        elif vector["operation"] == "resolve-settlement-group":
            vector["guards"] = ["sb1-demos-id"] + (["sb2-group-raw-references"] if vector["expected"] == "indeterminate" else [])
    return vectors


def document() -> dict[str, Any]:
    vectors = build_vectors()
    return {
        "set": "pay-dem-execution-v0.1",
        "spec": "DACS-4 §9.5.9 DEM-1..DEM-7; DEMOS-MAPPING §A.2 native-send record profile; §9.5.1 PC-4/PC-7; §9.5.8 SB-2; §9.7.0 FV-5",
        "tier": "candidate",
        "description": (
            "Inclusion does not prove execution. Only a getTxByHash record from a "
            "pinned node that decodes under the native-send record profile and binds "
            "the retained hash, nonce, block, sender, recipient and OS amount with "
            "status confirmed and independent applied-payment authority succeeds; a bound failed record is a permanent failure; "
            "anything else is a substrate result without a second broadcast."
        ),
        "demosProfile": {
            "profile": "DEMOS-MAPPING §A.2 native-send record profile",
            "nodeSource": "kynesyslabs/node@61b8e75aa8db5e408c49e1c3a89db4d673f45578 (stabilisation)",
            "sdk": "@kynesyslabs/demosdk@4.0.16 sha512-nVhp1uC+tFGzhew9c8XIajTMmELopx7gd0joqqzDd2XyUuFDcqrda51NYqvX5C8+L3Xgnie/mRf7JRqZ7r3tHA==",
            "liveObservations": "node2-* vectors copy read-only node2.demos.sh getTxByHash responses of 2026-10-17; the node reported 61b8e75 with a dirty tree, so they are observations, not the source pin",
        },
        "fixtureVocabulary": {
            "statusIndex": "getTransactionStatus state for the retained hash (included, pending or unknown); never decisive",
            "inclusionObservation": "block identified for the retained hash, or null",
            "recordRead": "getTxByHash read: found (record and node pin), not-found or unavailable; appliedTransfer and appliedTransferAuthenticated model separate authenticated committed state-transition authority, never derived in production from status or edits",
            "otherGates": "verdicts of the FV, SB-1 and PB checks that compose with DEM-7 before delivery",
            "consumerAdmissions": "raw txRef and (jobId, phaseIndex) for every otherwise admitted pay-dem record; derive SB-1 IDs before grouping",
            "guards": "checks whose removal makes this vector fail",
        },
        "count": len(vectors),
        "hash": hashlib.sha256(canonicalize(vectors).encode("utf-8")).hexdigest(),
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
