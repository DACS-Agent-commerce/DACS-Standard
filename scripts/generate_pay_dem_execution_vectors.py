#!/usr/bin/env python3
"""Generate DACS-4 §9.5.9 DEM-1..DEM-7 pay-dem execution vectors."""

from __future__ import annotations

import argparse
import base64
import copy
import decimal
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/vectors/security/pay-dem-execution-v0.1.json"
sys.path.insert(0, str(ROOT / "scripts"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from jcs import canonicalize  # noqa: E402
from demos_json import stringify  # noqa: E402
from settlement_finality_reference import (  # noqa: E402
    BFT_CERTIFICATE_DOMAIN, CHAIN_AUTHORITY_DOMAIN, DEMOS_EXECUTION_DOMAIN, hash_value,
)

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
SAFE_MAX_OS = str(2**53 - 1)  # the largest amount the node serves as a JSON number
# A send whose recipient argument the client supplied with the optional 0x.
PREFIXED_SEND = ["native", {"nativeOperation": "send", "args": ["0x" + PAYEE_KEY, AMOUNT_OS]}]
# Longer than Python's 4,300-digit int() limit: readers compare it by spelling.
OVERSIZED_OS = "9" * 4301
OVERSIZED_PAYER_OS = "1" + "0" * 4320  # a committed balance that can pay it
CANONICAL = re.compile(r"0|[1-9][0-9]*")
# The rail's Demos network: the pinned RailDefinition's
# `consumerFinalityProfile.settlement` network and genesis (FV `demos:mainnet`
# naming). A Demos NetworkSpec is the bare `{kind: "demos"}`, so this is the
# rail's only signed network identity; a binding never supplies it.
NETWORK = {"networkId": "demos:mainnet", "genesisHash": _hex("genesis:demos:mainnet")}
OTHER_NETWORK = {"networkId": "demos:testnet", "genesisHash": _hex("genesis:demos:testnet")}
# The same network name over another sealed genesis (a replaced genesis).
OTHER_GENESIS = {"networkId": NETWORK["networkId"], "genesisHash": _hex("genesis:demos:other")}
SCHEDULED_HEIGHT = 500000  # a future gasFeeSeparation activation height


def block_id(number: int) -> str:
    """The block ID (block hash) of a block number: the hash of the fixture
    header of the rail network's canonical block at that number, whose
    transactions root includes that block's transaction."""
    return hash_value(block_header(number))


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# DEM-4's inclusion half: the FV `bft-final` verification of the transaction's
# inclusion (DACS-4 §9.7.0 FV-4..FV-7) under the rail's signed settlement
# profile, in the settlement-finality corpus's fixture codecs. The verifier
# trusts the validator set, the observation authorities and its own clock.
FINALITY_SIGNERS = {name: _signing_key("fv-" + name)
                    for name in ("rpc-a", "rpc-b", "rpc-c", "validator-a", "validator-b", "validator-c")}
FORGED_VALIDATORS = {name: _signing_key("forged-fv-" + name) for name in ("validator-a", "validator-b")}
VALIDATOR_SET = {"validators": [
    {"validatorId": name, "weight": weight, "publicKey": _b64u(FINALITY_SIGNERS[name].public_key().public_bytes_raw())}
    for name, weight in (("validator-a", 40), ("validator-b", 35), ("validator-c", 25))
]}


def finality_profile(network: dict[str, str] = NETWORK) -> dict[str, Any]:
    """The rail's signed `consumerFinalityProfile.settlement`: `bft-final`."""
    return {
        "kind": "bft-final", **network,
        "observation": {"method": "rpc-quorum", "authorityRefs": ["rpc-a", "rpc-b", "rpc-c"],
                        "threshold": 2, "maxHeadAgeSec": 60},
        "validatorSetRef": {"anchor": {"kind": "storage-program", "locator": "stor-" + _hex("validator-set")},
                            "contentHash": hash_value(VALIDATOR_SET)},
        "quorumNumerator": 2, "quorumDenominator": 3,
    }


FINALITY_PROFILE = finality_profile()
OBSERVED_AT = 1791649700000  # the authenticated head's observation, after the transfer
FINALITY_TRUST = {
    "validatorSets": {hash_value(VALIDATOR_SET): VALIDATOR_SET},
    "observationAuthorityKeys": {name: _b64u(FINALITY_SIGNERS[name].public_key().public_bytes_raw())
                                 for name in ("rpc-a", "rpc-b", "rpc-c")},
    "verificationTimeMs": OBSERVED_AT + 10000,
}
# A DEM-4 verifier's inputs for the inclusion half: the rail's profile and its own trust.
FINALITY = {"finalityProfile": FINALITY_PROFILE, "finalityTrust": FINALITY_TRUST}


def _transaction_proof(tx_hash: str, number: int, network: dict[str, str], sibling: str) -> dict[str, Any]:
    """The fixture Merkle proof that a block's transactions root includes
    the native transaction `tx_hash`."""
    body = {**network, "transactionRef": {"kind": "demos", "txHash": tx_hash, "blockNumber": number}, "txHash": tx_hash}
    raw = canonicalize(body).encode("utf-8")
    leaf = hashlib.sha256(b"\x00" + raw).hexdigest()
    sibling_hash = _hex("sibling:" + sibling)
    root = hashlib.sha256(b"\x01" + bytes.fromhex(leaf) + bytes.fromhex(sibling_hash)).hexdigest()
    return {"kind": "fixture-transaction-merkle-v1", "transactionBytes": _b64u(raw), "leafHash": leaf,
            "siblingHash": sibling_hash, "leafIndex": 0, "root": root}


def block_transaction(number: int) -> str:
    """The transaction a canonical fixture block includes: the live node2
    records' own blocks include them; every other block the retained one."""
    return {NODE2_FAILED["blockNumber"]: NODE2_FAILED["hash"],
            NODE2_CONFIRMED["blockNumber"]: NODE2_CONFIRMED["hash"]}.get(number, TX_HASH)


def block_header(number: int, *, network: dict[str, str] = NETWORK, branch: str = "canonical",
                 tx_hash: str | None = None) -> dict[str, Any]:
    tx_hash = block_transaction(number) if tx_hash is None else tx_hash
    return {**network, "position": str(number), "parentId": _hex(f"{branch}:block:{number - 1}"),
            "transactionsRoot": _transaction_proof(tx_hash, number, network, "block")["root"]}


def inclusion_proof(
    tx_hash: str | None = None, number: int = 0, *, network: dict[str, str] = NETWORK, branch: str = "canonical",
    head_branch: str | None = None, certified: bool = True,
    validators: dict[str, Ed25519PrivateKey] = FINALITY_SIGNERS, sibling: str = "block",
) -> dict[str, Any]:
    """FV's inclusion observation of the native transaction `tx_hash` in
    block `number` (by default the retained transfer's block), one
    authenticated block deep: the transaction Merkle proof, the inclusion
    block and its header, the head two observation authorities sign, and
    the BFT certificate two thirds of the validator weight signs. `branch`
    places the block on a fork; `head_branch` signs a head that does not
    descend from it; `certified=False` is a block not yet finalized;
    `sibling` proves a leaf that is not under the block's root."""
    number = number or BLOCK
    tx_hash = TX_HASH if tx_hash is None else tx_hash
    reference = {"kind": "demos", "txHash": tx_hash, "blockNumber": number}
    header = block_header(number, network=network, branch=branch, tx_hash=tx_hash)
    inclusion_id = hash_value(header)
    head = {**network, "position": str(number + 1),
            "parentId": inclusion_id if head_branch is None else _hex(f"{head_branch}:block:{number}"),
            "transactionsRoot": _hex("empty-root")}
    head_id = hash_value(head)
    observation: dict[str, Any] = {
        **network, "transactionRef": reference,
        "transactionInclusionProof": _transaction_proof(tx_hash, number, network, sibling),
        "inclusionBlock": {"id": inclusion_id, "parentId": header["parentId"], "position": str(number),
                           "header": _b64u(canonicalize(header).encode("utf-8"))},
        "authenticatedHead": {"id": head_id, "position": str(number + 1), "observedAt": OBSERVED_AT,
                              "header": _b64u(canonicalize(head).encode("utf-8"))},
        "ancestryProof": [{"childId": head_id, "parentId": inclusion_id, "position": str(number + 1),
                           "header": _b64u(canonicalize(head).encode("utf-8"))}],
    }
    digest = hash_value({**network, "headId": head_id, "headPosition": str(number + 1), "observedAt": OBSERVED_AT,
                         "pathDigest": hash_value([inclusion_id, head_id])})
    observation["authorityEvidence"] = {
        "kind": "fixture-threshold-signature-v1", "sourceRefs": ["rpc-a", "rpc-b", "rpc-c"],
        "attestations": [
            {"authorityRef": name, "algorithm": "ed25519",
             "value": _b64u(FINALITY_SIGNERS[name].sign((CHAIN_AUTHORITY_DOMAIN + digest).encode("ascii")))}
            for name in ("rpc-a", "rpc-b")
        ],
    }
    if certified:
        observation["finalityCertificate"] = {
            "kind": "fixture-bft-certificate-v1", "validatorSetHash": hash_value(VALIDATOR_SET),
            "blockId": inclusion_id,
            "signatures": [
                {"validatorId": name, "algorithm": "ed25519",
                 "value": _b64u(validators[name].sign((BFT_CERTIFICATE_DOMAIN + inclusion_id).encode("ascii")))}
                for name in ("validator-a", "validator-b")
            ],
        }
    return observation


# FV-5's independent Demos execution-result source (DACS-4 §9.7.0 FV-5, the
# settlement-finality corpus's `fixture-independent-results-v1` policy). The
# verifier trusts these authority keys and threshold. Each authority signs a
# result over the FV domain, and a result counts only when that many distinct
# keys verify. The forged source claims the same authority names under keys
# the policy does not hold. A flag or label that says a record is
# authenticated is no result.
FV5_SIGNERS = {name: _signing_key("fv5-" + name) for name in ("execution-a", "execution-b", "execution-c")}
FORGED_FV5_SIGNERS = {name: _signing_key("forged-fv5-" + name) for name in FV5_SIGNERS}
FV5_POLICY = {
    "kind": "fixture-independent-results-v1",
    "threshold": 2,
    "authorityKeys": {name: _b64u(key.public_key().public_bytes_raw()) for name, key in FV5_SIGNERS.items()},
}


def execution_result(
    value: dict[str, Any], *, network: dict[str, str] | None = None, block: str | None = None,
    signers: tuple[str, ...] = ("execution-a", "execution-b"), keys: dict[str, Ed25519PrivateKey] = FV5_SIGNERS,
    applied: dict[str, str] | None = None, applied_changes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """FV-5's signed execution result for the record `value` on `network`,
    in the settlement-finality corpus's form: it names the network, the
    inclusion block ID (by default the observed inclusion's), the record's
    own hash and block, and carries the record itself. With `applied`
    committed balances it also carries that corpus's optional signed
    `appliedTransfer`: the record's transaction and parties, and the debit
    and credit those balances change."""
    network = NETWORK if network is None else network
    number = value.get("blockNumber")
    result = {
        "kind": FV5_POLICY["kind"],
        "networkId": network["networkId"], "genesisHash": network["genesisHash"],
        "blockId": INCLUDED_AT_BLOCK["blockId"] if block is None else block,
        "transactionRef": {"kind": "demos", "txHash": value.get("hash"), "blockNumber": number},
        "record": copy.deepcopy(value),
    }
    if applied is not None:
        debit, credit = committed_change(applied)
        result["appliedTransfer"] = {
            "txHash": value["hash"], "blockNumber": number,
            "sender": value["content"]["from"].removeprefix("0x").lower(),
            "recipient": value["content"]["to"].removeprefix("0x").lower(),
            "payerDebitOs": debit, "payeeCreditOs": credit, "committedBalances": dict(applied),
            **(applied_changes or {}),
        }
    digest = hash_value(result)
    result["attestations"] = [
        {"authorityRef": signer, "algorithm": "ed25519",
         "value": _b64u(keys[signer].sign((DEMOS_EXECUTION_DOMAIN + digest).encode("ascii")))}
        for signer in signers
    ]
    return result


# DEMOS-MAPPING §A.2 node pin. A read's `nodeBuild` is the build attestation
# that the Demos binding configuration holds for the node that served it; the
# node's own self-report is not one.
NODE_COMMIT = "61b8e75aa8db5e408c49e1c3a89db4d673f45578"
TESTNET_COMMIT = "ac8f45f02fc9c25082ce9b83595c2e3916b49c5a"
PINNED_BUILD = {"source": "binding-attestation", "commit": NODE_COMMIT, "tree": "clean"}
SELF_REPORTED_BUILD = dict(PINNED_BUILD, source="self-reported")
OLD_BUILD = dict(PINNED_BUILD, commit=TESTNET_COMMIT)
DIRTY_BUILD = dict(PINNED_BUILD, tree="dirty")

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


def binding_entry(network: dict[str, str] = NETWORK, **members: Any) -> dict[str, Any]:
    """One network's entry in the payer's Demos binding configuration. Each
    member names the network and genesis it was configured or attested for:
    nodes pinned under the native-send record profile, an applied-payment
    authority, and the sealed genesis's `forks.gasFeeSeparation` activation
    height. `_OMIT` drops a member: the binding holds none."""
    return _apply(
        {
            **network,
            "pinnedNodes": dict(network),
            "appliedPaymentAuthority": dict(network),
            "gasFeeSeparation": dict(network, activationHeight=None),
        },
        members,
    )


def demos_binding(pinned_node: Any = True, applied_authority: Any = True,
                  fee_separation_unscheduled: Any = True) -> list[dict[str, Any]]:
    """The payer's binding with one entry, for the rail's network. Each
    argument is True (the member for that network), False (no pinned node or
    authority; a scheduled height for the fork), `_OMIT` (no member) or the
    member itself."""
    members: dict[str, Any] = {}
    for member, value in (("pinnedNodes", pinned_node), ("appliedPaymentAuthority", applied_authority)):
        if value is False or value is _OMIT:
            members[member] = _OMIT
        elif value is not True:
            members[member] = value
    if fee_separation_unscheduled is False:
        members["gasFeeSeparation"] = dict(NETWORK, activationHeight=SCHEDULED_HEIGHT)
    elif fee_separation_unscheduled is not True:
        members["gasFeeSeparation"] = fee_separation_unscheduled
    return [binding_entry(**members)]


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


_SERVED = object()


def served_edits(content: dict[str, Any], tx_hash: str) -> list[dict[str, Any]] | None:
    """The four `gcr_edits` a pinned node stores and serves with a native send:
    the SDK's edits with each `txhash` set to the transaction hash, as the
    live confirmed record shows. None when the send cannot generate them."""
    try:
        edits = native_send_edits(content)
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        return None
    return [dict(edit, txhash=tx_hash) for edit in edits]


# Fee recipients of a network whose genesis activates `gasFeeSeparation`: the
# pinned `data/genesis.json` treasury and a zero burn account.
FEE_BURN_ACCOUNT = "0x" + "0" * 64
FEE_TREASURY_ACCOUNT = "0xf7a1c3417e39563ca8f63f2e9a9ba08890888695768e95e22026e6f942addf23"


def fee_separated_edits(content: dict[str, Any], tx_hash: str) -> list[dict[str, Any]]:
    """The `gcr_edits` a pinned node stores for a native send once
    `gasFeeSeparation` is active: apply prepends `generateFeeDistributionEdits`
    (`handleGCR.ts`, `gcr_routines/feeDistribution.ts`) to the four send
    edits. Network fee split burn/treasury (the percentages are governance
    values; this split is illustrative), rpc fee folded to the treasury
    because `rpc_address` is null. The profile excludes such a network."""
    sender = content["from_ed25519_address"]

    def edit(operation: str, account: str, amount: int) -> dict[str, Any]:
        return {"type": "balance", "operation": operation, "isRollback": False,
                "account": account, "amount": amount, "txhash": tx_hash}

    return [edit("remove", sender, 1000000000), edit("add", FEE_BURN_ACCOUNT, 500000000),
            edit("add", FEE_TREASURY_ACCOUNT, 500000000), edit("remove", sender, 1000000000),
            edit("add", FEE_TREASURY_ACCOUNT, 1000000000)] + served_edits(content, tx_hash)


def record(
    status: str, content: dict[str, Any] | None = None, *, edits: Any = _SERVED, **changes: Any,
) -> dict[str, Any]:
    """A `getTxByHash` response record in the node's wire form: the send body
    plus the stored `timestamp`, fees and `gcr_edits` (the live records'
    shape). `edits` replaces the served edit list, and `_OMIT` drops it, which
    the pinned node applies as a successful no-op. The pinned apply stamps
    each edit's `txhash` only while it applies them, so a `failed` record's
    edits keep the empty hash, as the live failed record shows."""
    content = copy.deepcopy(send_content() if content is None else content)
    value = _apply({"hash": TX_HASH, "blockNumber": BLOCK, "status": status, "content": content}, changes)
    content.setdefault("timestamp", str(TIMESTAMP))
    content.setdefault("transaction_fee", {"network_fee": 1000000000, "rpc_fee": 1000000000, "additional_fee": 0, "rpc_address": None})
    if edits is _SERVED:
        stamped = value["hash"] if isinstance(value.get("hash"), str) else TX_HASH
        edits = served_edits(content, "" if status == "failed" else stamped)
    if edits is not _OMIT and edits is not None:
        content.setdefault("gcr_edits", edits)
    return value


def os_sum(left: str, right: str) -> str:
    """Exact sum of two canonical OS decimals, past int()'s digit limit."""
    with decimal.localcontext() as context:
        context.prec = max(len(left), len(right)) + 1
        return format(decimal.Decimal(left) + decimal.Decimal(right), "f")


def os_difference(left: str, right: str) -> str:
    """Exact difference of two canonical OS decimals; never negative here."""
    with decimal.localcontext() as context:
        context.prec = max(len(left), len(right)) + 1
        value = decimal.Decimal(left) - decimal.Decimal(right)
    if value < 0:
        raise ValueError("negative committed balance change")
    return format(value, "f")


# The scenario's committed state, independent of every RPC record: each
# account's balance immediately before the transaction's apply, and the 1 DEM
# gas an applied native send charges the payer.
PAYER_PRE_STATE_OS = "1" + "0" * 30
PAYEE_PRE_STATE_OS = "7" + "0" * 24
GAS_OS = "1000000000"


def committed(
    outcome: str = "applied", amount_os: str = AMOUNT_OS, *, payer_before: str = PAYER_PRE_STATE_OS,
) -> dict[str, str]:
    """The committed balance transition the fixture scenario fixes for its
    transaction, never read from the record: `applied` moves `amount_os` from
    payer to payee and charges the gas; a `rolled-back` apply (a failed send,
    or one the pinned node rejected after inclusion) and a `no-op` apply
    (missing or empty edits) leave both balances unchanged."""
    if outcome == "applied":
        moved, fee = amount_os, GAS_OS
    elif outcome in ("rolled-back", "no-op"):
        moved, fee = "0", "0"
    else:
        raise ValueError(outcome)
    return {
        "payerBeforeOs": payer_before,
        "payerAfterOs": os_difference(payer_before, os_sum(moved, fee)),
        "payeeBeforeOs": PAYEE_PRE_STATE_OS,
        "payeeAfterOs": os_sum(PAYEE_PRE_STATE_OS, moved),
        "feeOs": fee,
    }


APPLIED = committed()
ROLLED_BACK = committed("rolled-back")
NO_OP = committed("no-op")


def committed_change(balances: dict[str, str]) -> tuple[str, str]:
    """The payment debit (fee excluded) and payee credit of a committed
    balance transition: the authority's figures are this change."""
    payer_change = os_difference(balances["payerBeforeOs"], balances["payerAfterOs"])
    return (os_difference(payer_change, balances["feeOs"]),
            os_difference(balances["payeeAfterOs"], balances["payeeBeforeOs"]))


def with_state(read: dict[str, Any], balances: dict[str, str]) -> dict[str, Any]:
    """Give a read's authority another committed transition and its change."""
    debit, credit = committed_change(balances)
    read["appliedTransfer"].update(payerDebitOs=debit, payeeCreditOs=credit, committedBalances=dict(balances))
    return read


def found(
    value: dict[str, Any], *, authenticated: bool | None = None, node: dict[str, str] = PINNED_BUILD,
    applied: bool = True, applied_block_id: str | None = None, state: dict[str, str] = APPLIED,
    network: dict[str, str] = NETWORK, inclusion: Any = _SERVED,
) -> dict[str, Any]:
    """A found read. Its applied-payment authority reports the committed
    transition `state` that the scenario names (by default the phase's
    payment applied), whatever the record claims or carries as edits. Every
    read carries FV's bft-final inclusion observation of the retained
    transfer in the observed block, which every final verdict needs, unless
    `inclusion` replaces it (`_OMIT`: none). An `authenticated` read also
    carries FV-5's signed execution result for the record; a plain read
    does not."""
    read: dict[str, Any] = {"state": "found", "nodeBuild": dict(node), "record": value}
    if authenticated:
        read["executionResult"] = execution_result(value)
    if inclusion is _SERVED:
        read["inclusionProof"] = INCLUSION_PROOF
    elif inclusion is not _OMIT:
        read["inclusionProof"] = inclusion
    if applied:
        # Synthetic state-transition authority, separate from the RPC record:
        # it names the transaction it was asked about, and its debit and
        # credit are the change of the committed balances it authenticates.
        content = value["content"]
        debit, credit = committed_change(state)
        read["appliedTransferAuthenticated"] = True
        read["appliedTransfer"] = {
            "networkId": network["networkId"], "genesisHash": network["genesisHash"],
            "blockId": applied_block_id or block_id(int(value["blockNumber"])),
            "txHash": value["hash"].removeprefix("0x").lower(), "blockNumber": int(value["blockNumber"]),
            "sender": content["from"].removeprefix("0x").lower(),
            "recipient": content["to"].removeprefix("0x").lower(),
            "payerDebitOs": debit, "payeeCreditOs": credit,
            "committedBalances": dict(state),
        }
    return read


NOT_FOUND = {"state": "not-found"}
UNAVAILABLE = {"state": "unavailable"}
# The observed inclusion of the retained transfer: INCLUDED_AT_BLOCK, once TX_HASH is defined.
_OBSERVED = object()



def fv5_variants(value: dict[str, Any], *, proof: bool = False) -> list[tuple[str, str, Any, str]]:
    """What FV-5 must refuse for the record `value`, each with the check that
    refuses it: the earlier draft's flag (or, in a proof, its label), a
    forged result, too few signatures, and a signed result for another
    network, block or record. For a read the value is the read's added
    members; for a proof it is the proof's `authentication`. A proof has no
    inclusion observation of its own, so it has no block variant."""
    other = record("failed" if value.get("status") == "confirmed" else "confirmed")
    variants = [
        ("fv5-flag-only", "fv5-authentication-is-a-signed-result",
         "fv5-bft-final" if proof else {"authenticated": True},
         "Saying FV-5 authenticated the record, as the earlier draft's flag and label did, carries no signed result."),
        ("fv5-forged-result", "fv5-result-signed", execution_result(value, keys=FORGED_FV5_SIGNERS),
         "A result under the policy's authority names whose signatures verify under no policy key authenticates nothing."),
        ("fv5-result-below-threshold", "fv5-result-signed", execution_result(value, signers=("execution-a",)),
         "One authority's signature is below the policy threshold of two."),
        ("fv5-result-for-another-network", "fv5-result-binds-rail-network",
         execution_result(value, network=OTHER_NETWORK),
         "A signed result for another network does not authenticate the rail network's record."),
        ("fv5-result-for-another-block", "fv5-result-binds-block-id",
         execution_result(value, block=FORK_INCLUSION_PROOF["inclusionBlock"]["id"]),
         "A signed result that names another block ID than the observed inclusion authenticates nothing."),
        ("fv5-result-of-another-record", "fv5-result-binds-record", execution_result(other),
         "The authorities signed another record than this one, with another status; it authenticates this one nothing."),
    ]
    if proof:
        return [variant for variant in variants if variant[1] != "fv5-result-binds-block-id"]
    # Each signed result comes with the transfer's verifying bft-final
    # inclusion in the block it names (the other branch's, for the result of
    # another block), so only the result decides.
    return [(suffix, guard,
             value if suffix == "fv5-flag-only" else {
                 "executionResult": value,
                 "inclusionProof": FORK_INCLUSION_PROOF if guard == "fv5-result-binds-block-id" else INCLUSION_PROOF},
             note)
            for suffix, guard, value, note in variants]


def bft_final_variants() -> list[tuple[str, list[str], Any, str]]:
    """What DEM-4's inclusion half must refuse when FV-5's policy-signed
    result for the failed record verifies, each with the checks that refuse
    it and the inclusion observation (`_OMIT` for none). A failed result is
    terminal only with the FV `bft-final` verification of the transaction's
    inclusion in the block that result names; an implementation that takes
    the signed result alone accepts every one."""
    alone = "failure-requires-bft-final-inclusion"
    return [
        ("bft-final-inclusion-missing", [alone], _OMIT,
         "A verifying signed result with no inclusion observation shows the execution result, not its bft-final inclusion."),
        ("bft-final-inclusion-unfinalized", [alone, "bft-final-inclusion-verified"], inclusion_proof(certified=False),
         "The block that includes the transaction has no BFT finality certificate: it is not final."),
        ("bft-final-certificate-forged", [alone, "bft-final-inclusion-verified"],
         inclusion_proof(validators=FORGED_VALIDATORS),
         "A certificate under the validator names whose signatures verify under no key of the trusted validator set finalizes nothing."),
        ("bft-final-transaction-absent", [alone, "bft-final-inclusion-verified"], inclusion_proof(sibling="absent"),
         "The transaction proof does not reach the finalized block's transactions root: the transaction is not in that block."),
        ("bft-final-block-off-authenticated-head", [alone, "bft-final-inclusion-verified"],
         inclusion_proof(head_branch="fork"),
         "The authenticated head does not descend from the block: it is on another branch than the authenticated chain."),
        ("bft-final-inclusion-of-another-block", [alone, "bft-final-inclusion-binds-result-block"],
         inclusion_proof(branch="fork"),
         "A final block of another branch at the same height includes the transaction, but the signed result names the observed block."),
    ]


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


def fv_form_result_with(value: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """A policy-signed combined-form result for `value` whose applied payment
    is changed after the fact, then signed: what the authorities signed is
    the contradiction itself."""
    return execution_result(value, applied=APPLIED, applied_changes=changes)


def with_input(vector: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """The vector with members of its protocol input replaced."""
    return dict(vector, protocolInput=dict(vector["protocolInput"], **changes))


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
    inclusion: Any = _OBSERVED,
    transfer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _vector(
        name, "classify-execution",
        {
            "railNetwork": NETWORK,
            **FINALITY,
            "fv5Policy": FV5_POLICY,
            "retainedTransfer": retained() if transfer is None else transfer,
            "statusIndex": status_index,
            "inclusionObservation": INCLUDED_AT_BLOCK if inclusion is _OBSERVED else inclusion,
            "recordRead": read,
        },
        expected, handler_want(expected), rule, guards, note,
    )


def failure_proof(
    content: dict[str, Any] | None = None, *, authentication: Any = _OMIT, inclusion: Any = _SERVED,
    **record_changes: Any,
) -> dict[str, Any]:
    """A retained DEM-4 proof: the bound failed record, its authentication,
    the FV inclusion observation of its transaction, its classification and
    inclusion block. The authentication is FV-5's signed execution result for
    that record unless `authentication` replaces it (a label, a plain read
    or another result); the inclusion is the transfer's verifying bft-final
    inclusion unless `inclusion` replaces it (`_OMIT`: none retained)."""
    failed = record(record_changes.pop("status", "failed"), content, **record_changes)
    return _apply({
        "classification": "permanent",
        "authentication": execution_result(failed) if authentication is _OMIT else authentication,
        "inclusionProof": INCLUSION_PROOF if inclusion is _SERVED else inclusion,
        "inclusionBlock": BLOCK,
        "record": failed,
    }, {})


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
    inclusion: Any = _OBSERVED,
) -> dict[str, Any]:
    return _vector(
        name, "resume-phase",
        {
            "railNetwork": NETWORK,
            **FINALITY,
            "fv5Policy": FV5_POLICY,
            "retainedTransfer": retained(),
            "retainedFailureProof": proof,
            "statusIndex": status_index,
            "inclusionObservation": INCLUDED_AT_BLOCK if inclusion is _OBSERVED else inclusion,
            "recordRead": read,
        },
        expected, handler_want(expected), rule, guards, note,
    )


def dem_spelling(amount_os: str) -> str:
    """The DEM decimal of an OS amount (10^9 OS per DEM), without trailing zeros."""
    whole, fraction = divmod(int(amount_os), 10**9)
    fraction_digits = f"{fraction:09d}".rstrip("0")
    return f"{whole}.{fraction_digits}" if fraction_digits else str(whole)


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


TIMESTAMP = 1791649642726  # a `Date.now()` value, as `pay()` stamps it
SDK_FEES = {"network_fee": "1000000000", "rpc_fee": "1000000000", "additional_fee": "0", "rpc_address": None}
# demosdk 4.0.16 member order: the transaction skeleton, then the members
# `sign()` adds.
SDK_ORDER = (
    "type", "from", "to", "amount", "data", "nonce", "timestamp", "transaction_fee",
    "from_ed25519_address", "gcr_edits",
)


def native_send_edits(content: dict[str, Any]) -> list[dict[str, Any]]:
    """demosdk 4.0.16 `GCRGeneration.generate` for a native send, as `sign()`
    serializes it post-fork: debit, credit, 1 DEM gas and the nonce edit,
    with the empty `txhash` the SDK ships."""
    sender = content["from_ed25519_address"]
    to, amount = content["data"][1]["args"]
    account = to if to.startswith("0x") else "0x" + to
    amount = amount if isinstance(amount, str) else str(amount)
    return [
        {"type": "balance", "operation": "remove", "isRollback": False, "account": sender, "txhash": "", "amount": amount},
        {"type": "balance", "operation": "add", "isRollback": False, "account": account, "txhash": "", "amount": amount},
        {"type": "balance", "account": sender, "operation": "remove", "amount": "1000000000", "txhash": "", "isRollback": False},
        {"type": "nonce", "operation": "add", "account": sender, "amount": 1, "txhash": "", "isRollback": False},
    ]


def sdk_content(content: dict[str, Any], omit: tuple[str, ...] = ()) -> dict[str, Any]:
    """Complete a native-send body as `pay()` and `sign()` do: timestamp,
    node fees and regenerated edits, in the SDK's member order. `omit`
    leaves members out."""
    content = copy.deepcopy(content)
    content.setdefault("timestamp", TIMESTAMP)
    content.setdefault("transaction_fee", dict(SDK_FEES))
    content.setdefault("gcr_edits", native_send_edits(content))
    ordered = {key: content[key] for key in SDK_ORDER if key in content}
    ordered.update(content)
    return {key: value for key, value in ordered.items() if key not in omit}


def signed(
    content: dict[str, Any] | None = None,
    *,
    signer: Ed25519PrivateKey = PAYER_SIGNER,
    signed_content: dict[str, Any] | None = None,
    omit: tuple[str, ...] = (),
) -> dict[str, Any]:
    """The signed native transaction as demosdk 4.0.16 builds it: numeric
    nonce, OS-string amount, timestamp, node fees and regenerated edits,
    `hash` over the serialized content and an Ed25519 signature over the
    UTF-8 hash. `signed_content` hashes and signs other content than the
    transaction carries (a forged hash)."""
    if content is None:
        content = send_content(nonce=NONCE, amount=AMOUNT_OS)
    content = sdk_content(content, omit)
    if signed_content is not None:
        signed_content = sdk_content(signed_content, omit)
    tx_hash = content_hash(content if signed_content is None else signed_content)
    return {
        "content": content,
        "hash": tx_hash,
        "signature": {"type": "ed25519", "data": "0x" + signer.sign(tx_hash.encode("utf-8")).hex()},
    }


# The hash of the default signed transfer, which every default record cites.
TX_HASH = signed()["hash"]
INCLUDED_AT_BLOCK = {"blockNumber": BLOCK, "blockId": block_id(BLOCK)}
# FV's bft-final inclusion observation of the retained transfer in that block.
INCLUSION_PROOF = inclusion_proof()
# The same transfer's final inclusion at the same height on another branch,
# and in the other network's block.
FORK_INCLUSION_PROOF = inclusion_proof(branch="fork")
OTHER_NETWORK_BLOCK_ID = inclusion_proof(network=OTHER_NETWORK)["inclusionBlock"]["id"]
# The pinned node that answers the handler's `confirm`; it signs its validity data.
RPC_SIGNER = _signing_key("rpc-node")
CONFIRM_REFERENCE_BLOCK = BLOCK - 1


def validity_response(
    transaction: dict[str, Any],
    *,
    valid: bool = True,
    reference_block: int = CONFIRM_REFERENCE_BLOCK,
) -> dict[str, Any]:
    """demosdk 4.0.16 `confirm()` result (`RPCResponseWithValidityData`) from
    a node at 61b8e75: `confirmTx` embeds the transaction it received, in the
    SDK envelope, and signs SHA-256 of `JSON.stringify(data)` with its key.
    `broadcast(validationData)` sends this object, and the node executes
    `response.data.transaction`."""
    envelope = {key: transaction[key] for key in ("content", "signature", "hash") if key in transaction}
    data = {
        "valid": valid,
        "reference_block": reference_block,
        # The node's messages (validateTransaction.ts); the balance figures
        # are illustrative, and DEM-1 never reads `message`.
        "message": ("[Tx Validation] Transaction signature verified\n" if valid
                    else f"[Tx Validation] [BALANCE ERROR] Insufficient balance: need {AMOUNT_OS} but have 0\n"),
        "gas_operation": None,
        "transaction": dict(envelope, status="", blockNumber=None),
    }
    digest = hashlib.sha256(stringify(data).encode("utf-8")).hexdigest()
    return {
        "result": 200,
        "response": {
            "data": data,
            "signature": {"type": "ed25519", "data": "0x" + RPC_SIGNER.sign(digest.encode("utf-8")).hex()},
            "rpc_public_key": {"type": "ed25519", "data": "0x" + _key(RPC_SIGNER)},
        },
        "require_reply": False,
        "extra": None,
    }


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
    broadcast_state: str | None = None,
    request: str = "broadcast-retained",
    restarted: Any = False,
    pinned_node: Any = True,
    applied_authority: Any = True,
    fee_separation_unscheduled: Any = True,
    binding: list[dict[str, Any]] | None = None,
    phase_context: dict[str, Any] | None = None,
    confirm_response: Any = _OMIT,
    carried_response: Any = _OMIT,
) -> dict[str, Any]:
    """A `confirm` request carries the signed transaction itself. A demosdk
    `broadcast` carries a validity response: by default the one this
    submission's `confirm` returned, embedding the signed transaction.
    `binding` replaces the payer's whole Demos binding configuration."""
    transaction = signed() if signed_transaction is None else signed_transaction
    broadcasting = request.startswith("broadcast-")
    if broadcast_state is None:
        broadcast_state = "confirm-returned" if broadcasting else "never-broadcast"
    if confirm_response is _OMIT:
        confirm_response = validity_response(transaction) if broadcasting else None
    if carried_response is _OMIT:
        carried_response = confirm_response
    return _vector(
        name, "broadcast-gate",
        _apply({
            "phase": phase() if phase_context is None else phase_context,
            "railNetwork": NETWORK,
            "demosBinding": (demos_binding(pinned_node, applied_authority, fee_separation_unscheduled)
                             if binding is None else binding),
            "signedTransaction": transaction,
            "retainedTransfer": retained() if transfer is None else transfer,
            "hashRetainedForOtherPhases": retained_elsewhere or [],
            "retentionDurable": durable,
            "broadcastState": broadcast_state,
            "restartedSinceRetention": restarted,
            "confirmResponse": confirm_response,
            "request": request,
            "validityResponse": carried_response,
        }, {}),
        expected, {"broadcastPermitted": expected == "pass"}, rule, guards, note,
    )


def pre_sign(
    name: str,
    expected: str,
    guards: list[str],
    note: str,
    *,
    pinned_node: Any = True,
    applied_authority: Any = True,
    fee_separation_unscheduled: Any = True,
    binding: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """DEM-1 before `pay()`/`sign()`: the input holds no signed transaction,
    and a refusal is the PC-4 result itself. `_OMIT` drops a binding member:
    the binding attests nothing for it."""
    refused = expected != "pass"
    return _vector(
        name, "pre-sign-gate",
        _apply({
            "phase": phase(),
            "railNetwork": NETWORK,
            "demosBinding": (demos_binding(pinned_node, applied_authority, fee_separation_unscheduled)
                             if binding is None else binding),
        }, {}),
        expected,
        {
            "signPermitted": not refused,
            "ok": False if refused else None,
            "errorClass": "substrate" if refused else None,
        },
        "DEM-1/RAV-R4", guards, note,
    )


# Guards each party-address vector names (DEMOS-MAPPING §A.2).
PARTY_GUARDS = {
    "gate": ["first-broadcast-allowed", "phase-party-address-projects", "submission-completes-own-confirm"],
    "malformed": ["phase-party-address-projects", "submission-completes-own-confirm"],
    "admit": ["consumer-admits-confirmed", "phase-party-address-projects"],
    "malformed-admit": ["consumer-requires-confirmed-record", "phase-party-address-projects"],
}


def preflight(name: str, expected: str, guards: list[str], note: str, *, availability: str = "live",
              pinned_node: Any = True, applied_authority: Any = True,
              fee_separation_unscheduled: Any = True, binding: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """RAV-R3 for a new production session, before the rail is selected:
    `availability` and `railNetwork` are the pinned RailDefinition's, and the
    preflight finds the payer's Demos binding entry for that network."""
    return _vector(
        name, "rail-preflight",
        _apply({
            "availability": availability,
            "railNetwork": NETWORK,
            "demosBinding": (demos_binding(pinned_node, applied_authority, fee_separation_unscheduled)
                             if binding is None else binding),
        }, {}),
        expected, {"railSelectable": expected == "pass"}, "RAV-R3/DEM-1", guards, note,
    )


def consistent(
    content: dict[str, Any] | None = None,
    signer: Ed25519PrivateKey = PAYER_SIGNER,
    *,
    signed_content: dict[str, Any] | None = None,
    omit: tuple[str, ...] = (),
    **retained_changes: Any,
) -> dict[str, Any]:
    """A signed transaction and a retention that cites its hash, so a gate
    vector differs from the control only in what it names."""
    transaction = signed(content, signer=signer, signed_content=signed_content, omit=omit)
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
        "railNetwork": NETWORK,
        **FINALITY,
        "fv5Policy": FV5_POLICY,
        "inclusionObservation": INCLUDED_AT_BLOCK,
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
        # A live block's ID is not in the fixture: the observation names its number only.
        protocol_input["inclusionObservation"] = {"blockNumber": signed_evidence["txRef"]["blockNumber"]}
    if phase_context is not None:
        protocol_input["phase"] = phase_context
    # DEM-7 alone is one gate: it never authorizes delivery by itself.
    return _vector(
        name, "admit-evidence", protocol_input, expected,
        {"dem7GatePassed": expected == "pass", "deliveryAuthorized": False},
        rule, guards, note,
    )


ALL_GATES_PASS = {"fv": "pass", "sb1": "pass", "pb": "pass"}


def _admission(admission: dict[str, Any]) -> dict[str, Any]:
    """One raw admitted reference: `txHash` overrides the canonical spelling
    and `legacy` marks verified legacy evidence."""
    return _apply(
        {
            "jobId": admission["jobId"],
            "phaseIndex": admission["phaseIndex"],
            "txRef": {"kind": "demos", "txHash": admission.get("txHash", TX_HASH), "blockNumber": BLOCK},
            "legacy": admission.get("legacy", _OMIT),
        },
        {},
    )


def not_sent_want() -> dict[str, Any]:
    """PC-4 result of a refusal before the first egress: nothing carried the
    signed bytes, so no node holds them and the phase ends permanent."""
    return dict(
        handler_want("fail"),
        executionState="not-sent", evidence="none", terminalFailureProofRetained=False,
    )


def egress(
    name: str,
    expected: str,
    rule: str,
    guards: list[str],
    note: str,
    *,
    call: str,
    outcome: str,
    broadcast_state: str | None = None,
    restarted: Any = False,
) -> dict[str, Any]:
    """The handler's own pre-egress check, `confirm` or `broadcast` has
    returned `outcome`; `broadcastState` and `restartedSinceRetention` are
    what the handler reads back from its journal, as at `broadcast-gate`."""
    if broadcast_state is None:
        broadcast_state = "confirm-returned" if call == "broadcast" else "never-broadcast"
    cause = f"{call}:{outcome}"
    want = not_sent_want() if expected == "fail" else handler_want(expected)
    return _vector(
        name, "classify-egress-outcome",
        {
            "broadcastState": broadcast_state,
            "restartedSinceRetention": restarted,
            "call": call,
            "outcome": outcome,
        },
        expected, dict(want, cause=cause), rule, guards, note,
    )


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
    index: Any = _OMIT,
    dem7_passed: bool = True,
    phase_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """`index` is the payee's durable admission index as read for this check:
    by default exactly the presented history; a list builds a snapshot of
    other admissions, and None or a dict is passed through as given."""
    protocol_input = _admit_input(
        found(record("confirmed"), authenticated=True) if read is None else read, "included"
    )
    if phase_context is not None:
        protocol_input["phase"] = phase_context
    protocol_input["otherGates"] = _apply(ALL_GATES_PASS, gates or {})
    presented = [_admission(admission) for admission in (admissions or [])]
    protocol_input["consumerAdmissions"] = presented
    if index is _OMIT:
        index = {"revision": len(presented), "admissions": [dict(admission) for admission in presented]}
    elif isinstance(index, list):
        index = {"revision": len(index), "admissions": [_admission(admission) for admission in index]}
    protocol_input["admissionIndex"] = index
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
    # After a retained DEM-4 result the phase has ended: an inclusion-only
    # success on the re-read is also refused as post-terminal (DEM-6).
    post_terminal = ["unresolved-authorizes-nothing"]
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
        # DEM-3 and PC-7: the same bound confirmed record and its applied
        # payment are no success until the transaction's inclusion in the
        # observed block is bft-final.
        *(
            classify(
                "included-confirmed-" + suffix, "indeterminate", "DEM-3/PC-7",
                ["success-requires-bft-final-inclusion",
                 *(guard for guard in guards if guard != "failure-requires-bft-final-inclusion")] + unresolved,
                note.replace("signed result names", "observation names").replace(
                    "A verifying signed result", "A bound confirmed record and its applied payment"),
                read=found(record("confirmed"), inclusion=inclusion),
            )
            for suffix, guards, inclusion, note in bft_final_variants()
        ),
        with_input(classify(
            "included-confirmed-bft-final-profile-of-another-network", "indeterminate", "DEM-3/PC-7",
            ["bft-final-inclusion-verified", "success-requires-bft-final-inclusion"] + unresolved,
            "An inclusion that verifies under another network's bft-final profile is not under the rail's signed profile.",
            read=found(record("confirmed"), inclusion=inclusion_proof(network=OTHER_NETWORK),
                       applied_block_id=OTHER_NETWORK_BLOCK_ID),
            inclusion=dict(INCLUDED_AT_BLOCK, blockId=OTHER_NETWORK_BLOCK_ID),
        ), finalityProfile=finality_profile(OTHER_NETWORK)),
        classify(
            "node2-confirmed-record", "indeterminate", "DEM-2/DEM-3", ["success-requires-applied-transfer"] + unresolved,
            "The live confirmed RPC record has no independent applied-transfer authority.",
            # The observed block ID and its bft-final inclusion of the live
            # transaction are synthetic, like the fixture block's.
            read=found(copy.deepcopy(NODE2_CONFIRMED), applied=False,
                       inclusion=inclusion_proof(NODE2_CONFIRMED["hash"], NODE2_CONFIRMED["blockNumber"])),
            transfer=live_confirmed,
            inclusion=dict(live_confirmed_block, blockId=block_id(NODE2_CONFIRMED["blockNumber"])),
        ),
        classify(
            "confirmed-integer-nonce-binds", "pass", "DEM-2/DEM-3", ["success-authorizes-no-delivery", "success-branch"],
            "A safe JSON integer nonce projects to the same signed nonce.",
            read=found(record("confirmed", send_content(nonce=NONCE))),
        ),
        classify(
            "confirmed-large-string-amount-binds", "pass", "DEM-2/DEM-3", ["success-authorizes-no-delivery", "success-branch"],
            "Above 2^53 - 1 OS the node serves the amount as a decimal string; it binds by integer value.",
            read=found(record("confirmed", send_content(amount_os=LARGE_AMOUNT_OS)), state=committed(amount_os=LARGE_AMOUNT_OS)),
            transfer=retained(amountOs=LARGE_AMOUNT_OS),
        ),
        classify(
            "confirmed-unprefixed-parties-bind", "pass", "DEM-2/DEM-3", ["success-authorizes-no-delivery", "success-branch"],
            "A party key without the 0x prefix projects to the same DACS-1 key.",
            read=found(record("confirmed", send_content(**{"from": PAYER_KEY, "from_ed25519_address": PAYER_KEY, "to": PAYEE_KEY}))),
        ),
        classify(
            "confirmed-prefixed-send-argument-binds", "pass", "DEM-2/DEM-3", ["success-authorizes-no-delivery", "success-branch"],
            "A send recipient argument with the 0x prefix projects to the same key; its credit edit names it unchanged.",
            read=found(record("confirmed", send_content(data=PREFIXED_SEND))),
        ),
        classify(
            "confirmed-safe-max-number-amount-binds", "pass", "DEM-2/DEM-3", ["success-authorizes-no-delivery", "success-branch"],
            "Up to 2^53 - 1 OS the node serves the amount as a JSON number; that bound itself decodes.",
            read=found(record("confirmed", send_content(amount_os=SAFE_MAX_OS)), state=committed(amount_os=SAFE_MAX_OS)),
            transfer=retained(amountOs=SAFE_MAX_OS),
        ),
        classify(
            "included-failed", "fail", "DEM-4/DEM-6", ["failure-is-permanent", "failure-proof-retained", "no-replacement", "success-requires-record"],
            "Included is not executed: a bound failed record authenticated under FV-5 at its bft-final inclusion is a durable permanent failure with no replacement.",
            read=found(record("failed"), authenticated=True, state=ROLLED_BACK),
        ),
        # DEM-4 needs that authentication: the pin does not authenticate a
        # plain RPC read, and a stale or dishonest node can serve failed for a
        # transfer that executed, so a plain-read failure is only unresolved.
        classify(
            "included-failed-plain-read", "indeterminate", "DEM-4/DEM-5", ["failure-requires-authentication"] + unresolved,
            "A bound failed record from a plain RPC read is unresolved: substrate, re-read, never a terminal failure.",
            read=found(record("failed"), state=ROLLED_BACK),
        ),
        classify(
            "failed-plain-read-over-applied-payment", "indeterminate", "DEM-4/DEM-5", ["failure-requires-authentication"] + unresolved,
            "A pinned node serves failed for a transfer whose committed payment applied: a plain read never ends the phase.",
            read=found(record("failed")),
        ),
        # FV-5 is its signed execution result, verified against the trusted
        # policy: anything less leaves the failed record unresolved.
        *(
            classify(
                "included-failed-" + suffix, "indeterminate", "DEM-4/DEM-5/FV-5",
                ["failure-requires-authentication", guard] + unresolved, note,
                read=dict(found(record("failed"), state=ROLLED_BACK), **members),
            )
            for suffix, guard, members, note in fv5_variants(record("failed"))
        ),
        classify(
            "node2-included-failed-record", "indeterminate", "DEM-2/DEM-4/DEM-5", ["failure-requires-authentication"] + unresolved,
            "A live node2 transfer whose status index said included while its record failed (TX_NONCE_INVALID_LOW), read by plain RPC: unresolved.",
            read=found(copy.deepcopy(NODE2_FAILED), state=ROLLED_BACK), transfer=live_failed, inclusion=live_failed_block,
        ),
        classify(
            "node2-failed-record-authenticated", "fail", "DEM-2/DEM-4", ["failure-is-permanent", "failure-proof-retained", "no-replacement", "success-requires-record"],
            "The same live failed record, authenticated under FV-5 at its bft-final inclusion, is the DEM-4 terminal failure.",
            # FV-5 binds the observed inclusion block ID, so this observation
            # names one (synthetic, like the signed result and the fixture
            # block's bft-final inclusion of the live transaction).
            read=dict(found(copy.deepcopy(NODE2_FAILED), state=ROLLED_BACK),
                      executionResult=execution_result(NODE2_FAILED, block=block_id(NODE2_FAILED["blockNumber"])),
                      inclusionProof=inclusion_proof(NODE2_FAILED["hash"], NODE2_FAILED["blockNumber"])),
            transfer=live_failed, inclusion=dict(live_failed_block, blockId=block_id(NODE2_FAILED["blockNumber"])),
        ),
        # DEM-4's other half: the signed failed result verifies, yet without
        # FV's bft-final verification of the transaction's inclusion in the
        # block that result names the failure is not proven.
        *(
            classify(
                "included-failed-" + suffix, "indeterminate", "DEM-4/DEM-5/FV-5",
                ["failure-requires-authentication", *guards] + unresolved, note,
                read=_apply(found(record("failed"), authenticated=True, state=ROLLED_BACK), {"inclusionProof": inclusion}),
            )
            for suffix, guards, inclusion, note in bft_final_variants()
        ),
        # The verifier's profile must be the rail's: this inclusion verifies
        # under the other network's profile it was given, in the block that
        # the result and the observation name.
        with_input(classify(
            "included-failed-bft-final-profile-of-another-network", "indeterminate", "DEM-4/DEM-5/FV-5",
            ["bft-final-inclusion-verified", "failure-requires-authentication", "failure-requires-bft-final-inclusion"]
            + unresolved,
            "An inclusion that verifies under another network's bft-final profile is not under the rail's signed profile.",
            read=dict(found(record("failed"), authenticated=True, state=ROLLED_BACK),
                      executionResult=execution_result(record("failed"), block=OTHER_NETWORK_BLOCK_ID),
                      inclusionProof=inclusion_proof(network=OTHER_NETWORK)),
            inclusion=dict(INCLUDED_AT_BLOCK, blockId=OTHER_NETWORK_BLOCK_ID),
        ), finalityProfile=finality_profile(OTHER_NETWORK)),
        classify(
            "included-failed-fv-form-result", "fail", "DEM-2/DEM-4/FV-5",
            ["failure-is-permanent", "failure-proof-retained", "no-replacement", "success-requires-record"],
            "FV-5's signed result in the settlement-finality corpus's combined form, whose appliedTransfer shows the rolled-back apply, proves the failure.",
            read=dict(found(record("failed"), authenticated=True, state=ROLLED_BACK),
                      executionResult=execution_result(record("failed"), applied=ROLLED_BACK)),
        ),
        classify(
            "included-failed-fv-form-result-shows-payment", "indeterminate", "DEM-4/DEM-5/FV-5",
            ["failure-requires-authentication", "fv5-result-applied-transfer-binds-record"] + unresolved,
            "A signed failed record whose own signed appliedTransfer shows the payment applied contradicts itself: no proven failure.",
            read=dict(found(record("failed"), authenticated=True, state=ROLLED_BACK),
                      executionResult=execution_result(record("failed"), applied=APPLIED)),
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
            "confirmed-unpinned-node", "indeterminate", unbound, ["node-build-attested"] + unresolved,
            "A node that only self-reports the pinned commit is not pinned; it may store a failed transfer as confirmed.",
            read=found(record("confirmed"), node=SELF_REPORTED_BUILD),
        ),
        classify(
            "failed-unpinned-node", "indeterminate", unbound, ["failure-requires-binding", "node-build-attested"] + unresolved,
            "A failed record from an unpinned node proves nothing about execution either.",
            read=found(record("failed"), node=SELF_REPORTED_BUILD, authenticated=True, state=ROLLED_BACK),
        ),
        classify(
            "confirmed-old-build-node", "indeterminate", unbound, ["node-build-commit"] + unresolved,
            "An attested testnet ac8f45f build stores every block transaction as confirmed; it is not the pinned commit.",
            read=found(record("confirmed"), node=OLD_BUILD),
        ),
        classify(
            "confirmed-dirty-build-node", "indeterminate", unbound, ["node-build-clean-tree"] + unresolved,
            "The pinned commit built from a modified tree is not the pin.",
            read=found(record("confirmed"), node=DIRTY_BUILD),
        ),
        # A confirmed record whose transaction carries no edits: the pinned node
        # applies it as a successful no-op, so no payment moved.
        classify(
            "confirmed-no-op-apply", "indeterminate", "DEM-3/DEM-5", unresolved,
            "A confirmed send with no gcr_edits applied nothing: the committed balances did not change.",
            read=found(record("confirmed", edits=_OMIT), state=NO_OP),
        ),
        classify(
            "confirmed-no-op-empty-edits", "indeterminate", "DEM-3/DEM-5", unresolved,
            "An empty edit list is the same no-op; confirmed is not payment.",
            read=found(record("confirmed", edits=[]), state=NO_OP),
        ),
        classify(
            "confirmed-no-op-copied-authority", "indeterminate", "DEM-3/DEM-5", ["confirmed-requires-send-edits"] + unresolved,
            "An authority that reports a committed payment for a record without its send's edits cannot establish payment.",
            read=found(record("confirmed", edits=_OMIT)),
        ),
        # The edits must equal the send's four edits exactly: a partial list or
        # reordered members is not that list, whatever the authority reports.
        classify(
            "confirmed-partial-edits", "indeterminate", "DEM-3/DEM-5", ["confirmed-requires-send-edits"] + unresolved,
            "A confirmed record carrying only the payment's two balance edits is not the send's four edits.",
            read=found(record("confirmed", edits=served_edits(send_content(), TX_HASH)[:2])),
        ),
        classify(
            "confirmed-reordered-edit-members", "indeterminate", "DEM-3/DEM-5", ["confirmed-requires-send-edits"] + unresolved,
            "Edit members in another order serialize differently from the send's edits.",
            read=found(record("confirmed", edits=[dict(reversed(list(served_edits(send_content(), TX_HASH)[0].items())))]
                              + served_edits(send_content(), TX_HASH)[1:])),
        ),
        # With `gasFeeSeparation` active the node prepends fee-distribution
        # edits at apply: such a network is outside the profile, and DEM-1
        # never signs for it.
        classify(
            "confirmed-fee-separated-edits", "indeterminate", "DEM-3/DEM-5", ["confirmed-requires-send-edits"] + unresolved,
            "A record from a network with gasFeeSeparation active carries fee edits before the send's four: outside the profile.",
            read=found(record("confirmed", edits=fee_separated_edits(send_content(), TX_HASH))),
        ),
        classify(
            "confirmed-fee-separated-edits-uncommitted-payment", "indeterminate", "DEM-3/DEM-5", unresolved,
            "A fee-separated record whose authenticated committed balances did not move is still only unresolved for the handler.",
            read=found(record("confirmed", edits=fee_separated_edits(send_content(), TX_HASH)), state=ROLLED_BACK),
        ),
        # A confirmed record that carries its send's four edits, while the
        # authenticated committed state shows no payment: the edits are the
        # claim, the committed balances are the evidence.
        classify(
            "confirmed-four-edits-uncommitted-payment", "indeterminate", "DEM-3/DEM-5",
            ["success-requires-applied-transfer"] + unresolved,
            "Committed balances unchanged by a confirmed send with all four edits: no payment moved.",
            read=found(record("confirmed"), state=ROLLED_BACK),
        ),
        classify(
            "confirmed-four-edits-authority-not-committed-change", "indeterminate", "DEM-3/DEM-5",
            ["applied-transfer-is-committed-change", "success-requires-applied-transfer"] + unresolved,
            "An authority whose debit and credit copy the amount while its committed balances did not change establishes nothing.",
            read=_apply(found(record("confirmed")), {"appliedTransfer": dict(
                found(record("confirmed"))["appliedTransfer"], committedBalances=dict(ROLLED_BACK))}),
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
            # The authority names the observed block ID, so only the DEM-2 block binding refuses it.
            read=found(record("confirmed", blockNumber=BLOCK + 1), applied_block_id=block_id(BLOCK)),
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
            # The chain committed the transfer the record shows, so only the DEM-2 amount binding refuses it.
            read=found(record("confirmed", send_content(amount_os=OTHER_AMOUNT_OS)), state=committed(amount_os=OTHER_AMOUNT_OS)),
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
            # Skipping only the DEM-2 block check still leaves the applied-payment
            # authority without a block ID to bind, so bind-block alone does not flip it.
            "confirmed-without-inclusion-observation", "indeterminate", unbound, ["bind-requires-inclusion"],
            "Without an inclusion observation neither the record's block nor the applied-payment authority's block ID can be bound.",
            read=found(record("confirmed")), status_index="pending", inclusion=None,
        ),
        classify(
            "failed-wrong-nonce", "indeterminate", unbound, ["bind-nonce", "failure-requires-binding"] + unresolved,
            "A failed record with another nonce does not prove this transfer failed.",
            read=found(record("failed", send_content(nonce=str(NONCE + 1))), authenticated=True, state=ROLLED_BACK),
        ),
        classify(
            "failed-missing-nonce", "indeterminate", unbound, ["decode-nonce"] + unresolved,
            "A failed record missing its nonce does not decode, so it proves nothing.",
            read=found(record("failed", send_content(nonce=_OMIT)), authenticated=True, state=ROLLED_BACK),
        ),
        classify(
            # The retained transfer's bft-final inclusion is in the observed
            # block, so DEM-4's inclusion half refuses this record as well.
            "failed-wrong-block", "indeterminate", unbound, unresolved,
            "A failed record in another block conflicts with the inclusion observation.",
            read=found(record("failed", blockNumber=BLOCK + 1), authenticated=True, state=ROLLED_BACK),
        ),
        classify(
            "failed-wrong-amount", "indeterminate", unbound, ["bind-amount", "failure-requires-binding"] + unresolved,
            "A failed record for another amount does not prove this transfer failed.",
            read=found(record("failed", send_content(amount_os=OTHER_AMOUNT_OS)), authenticated=True, state=ROLLED_BACK),
        ),
        classify(
            # The bft-final inclusion is the retained transaction's, not this one's.
            "failed-wrong-hash", "indeterminate", unbound, unresolved,
            "A failed record for another hash does not prove this transfer failed.",
            read=found(record("failed", hash=OTHER_TX_HASH), authenticated=True, state=ROLLED_BACK),
        ),
        classify(
            "failed-wrong-sender", "indeterminate", unbound, ["bind-sender", "failure-requires-binding"] + unresolved,
            "A failed record from another sender does not prove this transfer failed.",
            read=found(record("failed", send_content(sender=OTHER_KEY)), authenticated=True, state=ROLLED_BACK),
        ),
        classify(
            "failed-wrong-recipient", "indeterminate", unbound, ["bind-recipient", "failure-requires-binding"] + unresolved,
            "A failed record to another recipient does not prove this transfer failed.",
            read=found(record("failed", send_content(recipient=OTHER_KEY)), authenticated=True, state=ROLLED_BACK),
        ),
        classify(
            "failed-without-inclusion-observation", "indeterminate", unbound, ["bind-requires-inclusion"],
            "A failed record without an inclusion observation is not a bound failure, and FV-5 has no observed block ID to bind.",
            read=found(record("failed"), authenticated=True, state=ROLLED_BACK), status_index="unknown", inclusion=None,
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
            "resume-corrupted-failure-proof", "indeterminate", "DEM-4/DEM-6", ["bind-nonce", "no-rebroadcast", "resume-validates-failure-proof"] + post_terminal,
            "A retained proof whose nonce no longer binds is not reused; re-read only.",
            proof=failure_proof(send_content(nonce=str(NONCE + 1))), read=NOT_FOUND,
        ),
        resume(
            "resume-corrupted-failure-proof-recipient", "indeterminate", "DEM-4/DEM-6", ["bind-recipient", "no-rebroadcast", "resume-validates-failure-proof"] + post_terminal,
            "A retained proof for another recipient is not reused.",
            proof=failure_proof(send_content(recipient=OTHER_KEY)), read=NOT_FOUND,
        ),
        resume(
            # Its retained bft-final inclusion is in the transfer's own block too.
            "resume-corrupted-failure-proof-block", "indeterminate", "DEM-4/DEM-6", ["no-rebroadcast", "resume-validates-failure-proof"] + post_terminal,
            "A retained proof whose record is in another block than its inclusion block is not reused.",
            proof=failure_proof(blockNumber=BLOCK + 1), read=NOT_FOUND,
        ),
        resume(
            "resume-corrupted-failure-proof-status", "indeterminate", "DEM-4/DEM-6", ["no-rebroadcast", "resume-validates-failure-proof"] + post_terminal,
            "A retained proof whose record is not failed is not a failure proof.",
            proof=failure_proof(status="pending"), read=NOT_FOUND,
        ),
        resume(
            "resume-plain-read-failure-proof-not-reused", "indeterminate", "DEM-4/DEM-6",
            ["no-rebroadcast", "resume-requires-authenticated-proof", "resume-validates-failure-proof"] + post_terminal,
            "A retained proof built on a plain RPC read (an earlier draft's DEM-4) is not reused; the resume re-reads.",
            proof=failure_proof(authentication="rpc-read"), read=NOT_FOUND,
        ),
        # A resume verifies the stored FV-5 result itself; one that does not
        # verify, or the earlier draft's label, is not reused.
        *(
            resume(
                "resume-failure-proof-" + suffix + "-not-reused", "indeterminate", "DEM-4/DEM-6/FV-5",
                ["no-rebroadcast", "resume-requires-authenticated-proof", "resume-validates-failure-proof", guard]
                + post_terminal, note,
                proof=failure_proof(authentication=authentication), read=NOT_FOUND,
            )
            for suffix, guard, authentication, note in fv5_variants(record("failed"), proof=True)
        ),
        # ...and verifies the stored inclusion observation itself: a proof
        # whose result verifies but whose bft-final inclusion does not, or is
        # in another block than the result names, is not reused.
        *(
            resume(
                "resume-failure-proof-" + suffix + "-not-reused", "indeterminate", "DEM-4/DEM-6/FV-5",
                ["no-rebroadcast", "resume-requires-authenticated-proof", "resume-validates-failure-proof", *guards]
                + post_terminal, note,
                proof=failure_proof(inclusion=inclusion), read=NOT_FOUND,
            )
            for suffix, guards, inclusion, note in bft_final_variants()
        ),
        resume(
            "resume-plain-read-failure-then-authenticated-confirmed", "indeterminate", "DEM-4/DEM-6",
            ["resume-requires-authenticated-proof", "resume-validates-failure-proof", "terminal-never-reopens",
             "unresolved-authorizes-nothing"],
            "A phase ended on a plain-read failed record (an earlier draft's DEM-4). The proof is not reused, and the "
            "re-read that finds the bound confirmed record with its applied payment is post-terminal: it never reopens "
            "the phase as paid.",
            proof=failure_proof(authentication="rpc-read"), read=found(record("confirmed")),
        ),
        resume(
            "resume-failure-proof-no-longer-verifies-then-confirmed", "indeterminate", "DEM-4/DEM-6/FV-5",
            ["fv5-result-signed", "resume-requires-authenticated-proof", "resume-validates-failure-proof",
             "terminal-never-reopens", "unresolved-authorizes-nothing"],
            "A phase ended on a DEM-4 proof whose FV-5 result the payer's policy no longer verifies. The proof is not "
            "reused, and the re-read that finds the bound confirmed record with its applied payment is post-terminal: "
            "it never reopens the phase as paid.",
            proof=failure_proof(authentication=execution_result(record("failed"), keys=FORGED_FV5_SIGNERS)),
            read=found(record("confirmed")),
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
        resume(
            "resume-without-proof-confirmed-bft-final-inclusion-unfinalized", "indeterminate", "DEM-3/DEM-6/PC-7",
            ["bft-final-inclusion-verified", "success-requires-bft-final-inclusion", "success-requires-record",
             "unresolved-authorizes-nothing"],
            "A resume's re-read of an executed transfer in a block no BFT certificate finalizes is no success yet.",
            proof=None, read=found(record("confirmed"), inclusion=inclusion_proof(certified=False)),
        ),
        # First-broadcast gate.
        gate(
            "first-broadcast-after-durable-retention", "pass", "DEM-1",
            ["first-broadcast-allowed", "submission-completes-own-confirm"],
            "The single broadcast, carrying its own confirm's validity response, is allowed once the signed transfer is durably retained for this phase.",
        ),
        gate(
            "broadcast-prefixed-send-argument", "pass", "DEM-1",
            ["first-broadcast-allowed", "submission-completes-own-confirm"],
            "demosdk passes the send recipient through as given; a 0x-prefixed argument gets no second 0x in the credit edit.",
            **consistent(send_content(nonce=NONCE, amount=AMOUNT_OS, data=["native", {"nativeOperation": "send", "args": ["0x" + PAYEE_KEY, AMOUNT_OS]}])),
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
        # The signature verifies once respelled, so only the exact form refuses it.
        gate(
            "broadcast-signature-uppercase-hex", "fail", "DEM-1", ["signed-signature-form", "signed-transaction-authentic"],
            "The signature data is 0x and 128 lower-case hexadecimal digits.",
            signed_transaction=_apply(signed(), {"signature": {"type": "ed25519", "data": "0x" + signed()["signature"]["data"][2:].upper()}}),
        ),
        gate(
            "broadcast-signature-unprefixed-hex", "fail", "DEM-1", ["signed-signature-form", "signed-transaction-authentic"],
            "The signature data carries the 0x prefix.",
            signed_transaction=_apply(signed(), {"signature": {"type": "ed25519", "data": signed()["signature"]["data"][2:]}}),
        ),
        gate(
            "broadcast-signature-extra-member", "fail", "DEM-1", ["signed-signature-form", "signed-transaction-authentic"],
            "The signature object has exactly the members type and data.",
            signed_transaction=_apply(signed(), {"signature": dict(signed()["signature"], encoding="hex")}),
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
            "consumer-prefixed-send-argument-admitted", "pass", "DEM-7", ["consumer-admits-confirmed"],
            "A record whose send recipient argument carries the 0x prefix binds the same payee.",
            read=found(record("confirmed", send_content(data=PREFIXED_SEND))),
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
                amount={"amount": dem_spelling(live_confirmed["amountOs"]), "currency": "DEM"},
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
            "consumer-unpinned-node-refused", "indeterminate", "DEM-7", ["consumer-requires-confirmed-record", "node-build-attested"],
            "A confirmed record from a node that only self-reports the pinned commit is not admitted.",
            read=found(record("confirmed"), node=SELF_REPORTED_BUILD),
        ),
        admit(
            "consumer-old-build-node-refused", "indeterminate", "DEM-7", ["consumer-requires-confirmed-record", "node-build-commit"],
            "An attested build of another commit lacks the pinned execution-record semantics.",
            read=found(record("confirmed"), node=OLD_BUILD),
        ),
        admit(
            "consumer-dirty-build-node-refused", "indeterminate", "DEM-7", ["consumer-requires-confirmed-record", "node-build-clean-tree"],
            "The pinned commit built from a modified tree is not admitted.",
            read=found(record("confirmed"), node=DIRTY_BUILD),
        ),
        admit(
            "consumer-confirmed-no-op-apply", "fail", "DEM-7/FV-5",
            ["consumer-authenticated-contradiction-fails", "consumer-requires-confirmed-record", "success-requires-applied-transfer"],
            "Authenticated applied-payment authority shows the edit-less confirmed send moved nothing: the evidence is refuted.",
            read=found(record("confirmed", edits=[]), state=NO_OP),
        ),
        admit(
            "consumer-confirmed-no-op-copied-authority", "indeterminate", "DEM-7",
            ["confirmed-requires-send-edits", "consumer-requires-confirmed-record"],
            "An authority that reports a committed payment for a record without the send's edits is not admitted.",
            read=found(record("confirmed", edits=_OMIT)),
        ),
        admit(
            "consumer-partial-edits", "indeterminate", "DEM-7",
            ["confirmed-requires-send-edits", "consumer-requires-confirmed-record"],
            "A record carrying only the payment's two balance edits is not admitted.",
            read=found(record("confirmed", edits=served_edits(send_content(), TX_HASH)[:2])),
        ),
        admit(
            "consumer-reordered-edit-members", "indeterminate", "DEM-7",
            ["confirmed-requires-send-edits", "consumer-requires-confirmed-record"],
            "A record whose edit members are reordered is not admitted.",
            read=found(record("confirmed", edits=[dict(reversed(list(served_edits(send_content(), TX_HASH)[0].items())))]
                              + served_edits(send_content(), TX_HASH)[1:])),
        ),
        admit(
            "consumer-fee-separated-edits", "indeterminate", "DEM-7",
            ["confirmed-requires-send-edits", "consumer-requires-confirmed-record"],
            "A record carrying gasFeeSeparation fee edits before the send's four is outside the profile and not admitted.",
            read=found(record("confirmed", edits=fee_separated_edits(send_content(), TX_HASH))),
        ),
        admit(
            "consumer-fee-separated-edits-uncommitted-payment", "fail", "DEM-7/FV-5",
            ["consumer-authenticated-contradiction-fails", "consumer-requires-confirmed-record", "success-requires-applied-transfer"],
            "Authenticated committed balances that did not move refute a fee-separated record: DEM-7 decides the contradiction whatever the edits.",
            read=found(record("confirmed", edits=fee_separated_edits(send_content(), TX_HASH)), state=ROLLED_BACK),
        ),
        admit(
            "consumer-four-edits-uncommitted-payment", "fail", "DEM-7/FV-5",
            ["consumer-authenticated-contradiction-fails", "consumer-requires-confirmed-record", "success-requires-applied-transfer"],
            "Authenticated committed balances unchanged by a confirmed send with all four edits refute the payment.",
            read=found(record("confirmed"), state=ROLLED_BACK),
        ),
        admit(
            "consumer-four-edits-authority-not-committed-change", "indeterminate", "DEM-7",
            ["applied-transfer-is-committed-change", "consumer-requires-confirmed-record", "success-requires-applied-transfer"],
            "An authority whose debit and credit are not the change of its committed balances is not admitted.",
            read=_apply(found(record("confirmed")), {"appliedTransfer": dict(
                found(record("confirmed"))["appliedTransfer"], committedBalances=dict(ROLLED_BACK))}),
        ),
        admit(
            "consumer-wrong-hash-unauthenticated", "indeterminate", "DEM-7", ["consumer-binds-hash", "consumer-requires-confirmed-record"],
            "A record for another transaction hash does not bind the signed txHash.",
            read=found(record("confirmed", hash=OTHER_TX_HASH), authenticated=False),
        ),
        admit(
            "consumer-wrong-hash-authenticated", "fail", "DEM-7/FV-5",
            ["consumer-authenticated-contradiction-fails", "consumer-binds-hash", "consumer-requires-confirmed-record"],
            "Under FV-5 an authenticated record for another hash contradicts the signed txHash.",
            read=found(record("confirmed", hash=OTHER_TX_HASH), authenticated=True),
        ),
        admit(
            "consumer-failed-fails", "fail", "DEM-7/FV-5", ["consumer-failed-refutes", "consumer-requires-confirmed-record"],
            "A bound failed record, authenticated under FV-5, refutes the success evidence.",
            read=found(record("failed"), authenticated=True, state=ROLLED_BACK),
        ),
        admit(
            "consumer-failed-fv-form-result-fails", "fail", "DEM-7/FV-5",
            ["consumer-failed-refutes", "consumer-requires-confirmed-record"],
            "FV-5's signed result in the settlement-finality corpus's combined form, with its rolled-back appliedTransfer, refutes the evidence too.",
            read=dict(found(record("failed"), authenticated=True, state=ROLLED_BACK),
                      executionResult=execution_result(record("failed"), applied=ROLLED_BACK)),
        ),
        # A signed failure refutes the evidence only with the bft-final
        # inclusion of the presented reference in the block it names, as the
        # settlement-finality reference verifies the path first.
        *(
            admit(
                "consumer-failed-" + suffix, "indeterminate", "DEM-7/FV-5",
                ["consumer-failed-requires-authentication", "consumer-refutation-requires-bft-final-inclusion",
                 "consumer-requires-confirmed-record",
                 *(guard for guard in guards if guard != "failure-requires-bft-final-inclusion")],
                note.replace("A verifying signed result", "A verifying signed failure"),
                read=found(record("failed"), authenticated=True, state=ROLLED_BACK, inclusion=inclusion),
            )
            for suffix, guards, inclusion, note in bft_final_variants()
        ),
        admit(
            "consumer-wrong-payee-authenticated-bft-final-inclusion-unfinalized", "indeterminate", "DEM-7/FV-5",
            ["bft-final-inclusion-verified", "consumer-binds-payee", "consumer-refutation-requires-bft-final-inclusion",
             "consumer-requires-confirmed-record"],
            "A signed record paying another payee, in a block no BFT certificate finalizes, contradicts nothing yet.",
            read=found(record("confirmed", send_content(recipient=OTHER_KEY)), authenticated=True,
                       inclusion=inclusion_proof(certified=False)),
        ),
        admit(
            "consumer-failed-unauthenticated", "indeterminate", "DEM-7/FV-5",
            ["consumer-failed-requires-authentication", "consumer-requires-confirmed-record"],
            "A failed record from a plain RPC read is not an authenticated refutation; the evidence stays indeterminate.",
            read=found(record("failed"), authenticated=False, state=ROLLED_BACK),
        ),
        *(
            admit(
                "consumer-failed-" + suffix, "indeterminate", "DEM-7/FV-5",
                ["consumer-failed-requires-authentication", "consumer-requires-confirmed-record", guard], note,
                read=dict(found(record("failed"), state=ROLLED_BACK), **members),
            )
            for suffix, guard, members, note in fv5_variants(record("failed"))
        ),
        admit(
            "consumer-wrong-payee-unauthenticated", "indeterminate", "DEM-7", ["consumer-binds-payee", "consumer-requires-confirmed-record"],
            "An unauthenticated read that pays another payee does not satisfy DEM-7.",
            read=found(record("confirmed", send_content(recipient=OTHER_KEY)), authenticated=False),
        ),
        admit(
            "consumer-wrong-block-unauthenticated", "indeterminate", "DEM-7", ["consumer-binds-block", "consumer-requires-confirmed-record"],
            "An unauthenticated read in another block does not satisfy DEM-7.",
            read=found(record("confirmed", blockNumber=BLOCK + 1), authenticated=False),
        ),
        admit(
            "consumer-wrong-payer-unauthenticated", "indeterminate", "DEM-7", ["consumer-binds-payer", "consumer-requires-confirmed-record"],
            "An unauthenticated read from another payer does not satisfy DEM-7.",
            read=found(record("confirmed", send_content(sender=OTHER_KEY)), authenticated=False),
        ),
        admit(
            "consumer-wrong-amount-authenticated", "fail", "DEM-7/FV-5", ["consumer-authenticated-contradiction-fails", "consumer-binds-amount", "consumer-requires-confirmed-record"],
            "Under FV-5 an authenticated record for another amount is fail.",
            read=found(record("confirmed", send_content(amount_os=OTHER_AMOUNT_OS)), authenticated=True,
                       state=committed(amount_os=OTHER_AMOUNT_OS)),
        ),
        admit(
            "consumer-wrong-payee-authenticated", "fail", "DEM-7/FV-5", ["consumer-authenticated-contradiction-fails", "consumer-binds-payee", "consumer-requires-confirmed-record"],
            "Under FV-5 an authenticated record paying another payee is fail.",
            read=found(record("confirmed", send_content(recipient=OTHER_KEY)), authenticated=True),
        ),
        # Delivery: DEM-7 composed with FV-5 authentication, SB and PB.
        deliver(
            "delivery-after-all-gates", "pass", "DEM-7/FV-5", ["consumer-admits-confirmed"],
            "A bound confirmed record, FV-5-authenticated, with SB-1, SB-2 and PB passing, authorizes delivery.",
        ),
        # The FV gate's bft-final half is verified, never taken from a verdict.
        *(
            deliver(
                "delivery-" + suffix, "indeterminate", "DEM-7/FV-5",
                ["consumer-admits-confirmed", "delivery-requires-bft-final-inclusion",
                 *(guard for guard in guards if guard != "failure-requires-bft-final-inclusion")],
                note.replace("A verifying signed result", "A bound confirmed record with its verifying signed result"),
                read=found(record("confirmed"), authenticated=True, inclusion=inclusion),
            )
            for suffix, guards, inclusion, note in bft_final_variants()
        ),
        deliver(
            "delivery-record-unauthenticated", "indeterminate", "DEM-7/FV-5", ["consumer-admits-confirmed", "delivery-requires-authenticated-record"],
            "A bound confirmed record from a plain RPC read is not BFT-final proof; no delivery.",
            read=found(record("confirmed")),
        ),
        # FV-5's result in the settlement-finality corpus's combined form: the
        # form FV needs to pass a confirmed record carries the signed
        # appliedTransfer, which must bind the record it is signed with.
        deliver(
            "delivery-fv-form-result", "pass", "DEM-7/FV-5", ["consumer-admits-confirmed"],
            "A signed result that also carries its appliedTransfer, as the settlement-finality corpus signs it, authorizes delivery.",
            read=dict(found(record("confirmed"), authenticated=True),
                      executionResult=execution_result(record("confirmed"), applied=APPLIED)),
        ),
        deliver(
            "delivery-fv-form-result-applied-another-amount", "indeterminate", "DEM-7/FV-5",
            ["consumer-admits-confirmed", "delivery-requires-authenticated-record", "fv5-result-applied-transfer-binds-record"],
            "A signed result whose own appliedTransfer moved another amount than its confirmed record contradicts itself: no delivery.",
            read=dict(found(record("confirmed"), authenticated=True),
                      executionResult=execution_result(record("confirmed"), applied=committed(amount_os=OTHER_AMOUNT_OS))),
        ),
        deliver(
            "delivery-fv-form-result-applied-not-committed-change", "indeterminate", "DEM-7/FV-5",
            ["consumer-admits-confirmed", "delivery-requires-authenticated-record", "fv5-result-applied-transfer-binds-record"],
            "A signed appliedTransfer whose debit and credit are not the change of its committed balances establishes nothing.",
            read=dict(found(record("confirmed"), authenticated=True),
                      executionResult=fv_form_result_with(record("confirmed"), payerDebitOs="0")),
        ),
        deliver(
            "delivery-fv-form-result-applied-another-transaction", "indeterminate", "DEM-7/FV-5",
            ["consumer-admits-confirmed", "delivery-requires-authenticated-record", "fv5-result-applied-transfer-binds-record"],
            "A signed appliedTransfer for another transaction does not bind the record it is signed with.",
            read=dict(found(record("confirmed"), authenticated=True),
                      executionResult=fv_form_result_with(record("confirmed"), txHash=OTHER_TX_HASH)),
        ),
        *(
            deliver(
                "delivery-record-" + suffix, "indeterminate", "DEM-7/FV-5",
                ["consumer-admits-confirmed", "delivery-requires-authenticated-record", guard], note,
                read=dict(found(record("confirmed")), **members),
            )
            for suffix, guard, members, note in fv5_variants(record("confirmed"))
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
            "delivery-hash-admitted-legacy-spelling-for-another-job", "indeterminate", "DEM-7/SB-1/SB-2",
            ["consumer-admits-confirmed", "delivery-sb2-own-admissions", "sb1-demos-shape", "sb2-admitted-legacy-collapse"],
            "A verified legacy 0x/upper-case spelling admitted for another job collapses to the same demos:{txHash}; the group is indeterminate.",
            admissions=[{"jobId": OTHER_JOB_ID, "phaseIndex": PHASE_INDEX, "txHash": "0x" + TX_HASH.upper(), "legacy": True}],
        ),
        deliver(
            "delivery-admitted-reference-noncanonical", "error", "DEM-7/SB-1",
            ["consumer-admits-confirmed", "sb1-demos-canonical", "sb1-demos-shape", "sb2-admitted-malformed-error"],
            "An admitted current reference that cannot produce the canonical SB-1 key is malformed; it is never silently skipped.",
            admissions=[{"jobId": OTHER_JOB_ID, "phaseIndex": PHASE_INDEX, "txHash": "0x" + TX_HASH}],
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
        # The payee's history is the snapshot of its durable admission index:
        # a presented list that differs from it, or no index, is no history.
        deliver(
            "delivery-history-omits-indexed-admission", "error", "DEM-7/SB-2",
            ["consumer-admits-confirmed", "delivery-history-is-admission-index"],
            "The payee's admission index holds this hash for another job, but the presented history omits it, "
            "as a restart with process-local history would; the reused hash never delivers.",
            index=[{"jobId": OTHER_JOB_ID, "phaseIndex": PHASE_INDEX}],
        ),
        deliver(
            "delivery-history-adds-unindexed-admission", "error", "DEM-7/SB-2",
            ["consumer-admits-confirmed", "delivery-history-is-admission-index"],
            "A presented admission that the payee's index does not hold is not its snapshot: error.",
            admissions=[{"jobId": OTHER_JOB_ID, "phaseIndex": PHASE_INDEX}], index=[],
        ),
        deliver(
            "delivery-without-admission-index", "error", "DEM-7/SB-2",
            ["consumer-admits-confirmed", "delivery-requires-admission-index"],
            "Without a snapshot of the payee's durable admission index its history cannot be shown complete: error.",
            index=None,
        ),
        deliver(
            "delivery-admission-index-malformed-revision", "error", "DEM-7/SB-2",
            ["consumer-admits-confirmed", "delivery-requires-admission-index"],
            "An index snapshot whose revision is not a safe integer cannot be the conditional write's base: error.",
            index={"revision": "0", "admissions": []},
        ),
    ]
    # DEM-5/DEM-6 once the handler's own call returns: after the first egress
    # a node may hold the signed bytes, so a refusal, an error, a timeout or an
    # accepted broadcast leaves execution unresolved; only a refusal found
    # before any egress is permanent.
    vectors += [
        egress("egress-insufficient-balance-before-first-egress", "fail", "DEM-1/DEM-5",
               ["pre-egress-refusal-is-permanent"],
               "The handler's own balance read finds the payer short before any confirm or broadcast carried "
               "the signed transfer: permanent, nothing sent.",
               call="pre-egress-check", outcome="insufficient-balance"),
        egress("egress-insufficient-balance-after-restart", "indeterminate", "DEM-5/DEM-6",
               ["post-egress-refusal-is-unresolved", "restart-is-maybe-broadcast"],
               "After a restart a retained transfer may have left, whatever its journal records, so a short "
               "balance can be its own debit: substrate, re-read only.",
               call="pre-egress-check", outcome="insufficient-balance", restarted=True),
        egress("egress-insufficient-balance-after-interrupted-confirm", "indeterminate", "DEM-5/DEM-6",
               ["confirm-egress-may-broadcast", "post-egress-refusal-is-unresolved"],
               "A confirm that was cut off carried the signed bytes; a short balance afterwards proves nothing.",
               call="pre-egress-check", outcome="insufficient-balance", broadcast_state="confirm-sent-interrupted"),
        egress("egress-confirm-refused-insufficient-balance", "indeterminate", "DEM-5/DEM-6",
               ["post-egress-refusal-is-unresolved"],
               "demosdk confirm() throws valid false for insufficient balance after the node received the bytes: "
               "substrate with the retained hash kept, never permanent.",
               call="confirm", outcome="insufficient-balance"),
        egress("egress-confirm-refused-not-valid", "indeterminate", "DEM-5/DEM-6",
               ["post-egress-refusal-is-unresolved"],
               "Any confirm refusal comes from a node that holds the signed bytes: substrate.",
               call="confirm", outcome="refused-not-valid"),
        egress("egress-confirm-transport-error", "indeterminate", "DEM-5/DEM-6",
               ["call-error-is-unresolved"],
               "A confirm that errored may have reached the node: substrate, never transient, and no repeat.",
               call="confirm", outcome="transport-error"),
        egress("egress-confirm-timeout", "indeterminate", "DEM-5/DEM-6",
               ["call-error-is-unresolved"],
               "A confirm that timed out may have reached the node: substrate, and no repeat.",
               call="confirm", outcome="timeout"),
        egress("egress-confirm-unrecognized-outcome", "indeterminate", "DEM-5/DEM-6",
               ["call-error-is-unresolved"],
               "An unrecognized confirm reply is unresolved: fail closed to substrate.",
               call="confirm", outcome="http-418"),
        egress("egress-broadcast-transport-error", "indeterminate", "DEM-5/DEM-6",
               ["call-error-is-unresolved"],
               "demosdk broadcast() returns a 500 envelope on transport failure; the bytes may be in a mempool.",
               call="broadcast", outcome="transport-error"),
        egress("egress-broadcast-refused-not-valid", "indeterminate", "DEM-5/DEM-6",
               ["post-egress-refusal-is-unresolved"],
               "A broadcast refusal follows a confirm that already carried the bytes: substrate.",
               call="broadcast", outcome="refused-not-valid"),
        egress("egress-broadcast-refused-by-dem1-after-valid-confirm", "indeterminate", "DEM-5/DEM-6",
               ["post-egress-refusal-is-unresolved"],
               "The handler's own DEM-1 refusal of the completing broadcast comes after its confirm egress: "
               "substrate, re-read only.",
               call="broadcast", outcome="refused-by-dem1"),
        egress("egress-broadcast-accepted-is-not-success", "indeterminate", "DEM-3/DEM-5",
               ["success-requires-record"],
               "An accepted broadcast is not an executed transfer; the handler reads the record next.",
               call="broadcast", outcome="accepted"),
        egress("egress-balance-read-error-before-first-egress", "indeterminate", "DEM-5",
               ["call-error-is-unresolved"],
               "A Demos node or RPC failure is substrate for pay-dem, never PC-4 transient.",
               call="pre-egress-check", outcome="transport-error"),
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
        if name == "extra-send-argument":
            # A three-argument send has no regenerable edits, so the send-edit check refuses it too.
            guards = []
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
    # The rest of the demosdk sign() envelope the pinned node needs at admission.
    signed_body = send_content(nonce=NONCE, amount=AMOUNT_OS)
    control_edits = native_send_edits(signed_body)
    for name, guard, note, changes in (
        ("fee-object-missing", "signed-os-strings", "The signed fee object must be present.", {"omit": ("transaction_fee",)}),
        ("fee-member-missing", "signed-os-strings", "All three signed fee amounts must be present.",
         {"transaction_fee": {"network_fee": "1000000000", "additional_fee": "0", "rpc_address": None}}),
        ("numeric-rpc-fee", "signed-os-strings", "rpc_fee is a canonical OS string, never a DEM number.",
         {"transaction_fee": dict(SDK_FEES, rpc_fee=1_000_000_000)}),
        ("numeric-additional-fee", "signed-os-strings", "additional_fee is a canonical OS string, never a DEM number.",
         {"transaction_fee": dict(SDK_FEES, additional_fee=0)}),
        ("noncanonical-fee-string", "signed-os-strings", "A fee string with a leading zero is not canonical.",
         {"transaction_fee": dict(SDK_FEES, network_fee="01000000000")}),
        ("fee-members-reordered", "signed-fee-members",
         "The node rebuilds the fee object in network, rpc, additional, rpc_address order before re-deriving the hash.",
         {"transaction_fee": {"rpc_fee": "1000000000", "network_fee": "1000000000", "additional_fee": "0", "rpc_address": None}}),
        ("rpc-address-omitted", "signed-fee-members", "The node adds rpc_address null when it is absent, so the hash would not match.",
         {"transaction_fee": {"network_fee": "1000000000", "rpc_fee": "1000000000", "additional_fee": "0"}}),
        ("extra-fee-member", "signed-fee-members", "The node drops an extra fee member, so the hash would not match.",
         {"transaction_fee": dict(SDK_FEES, tip="1")}),
        ("timestamp-missing", "signed-timestamp", "The node converts the signed timestamp with BigInt; an absent one is refused.",
         {"omit": ("timestamp",)}),
        ("fractional-timestamp", "signed-timestamp", "A fractional timestamp is not a BigInt value.",
         {"timestamp": TIMESTAMP + 0.5}),
        ("timestamp-zero", "signed-timestamp", "sign() replaces a zero timestamp with Date.now(); zero is not positive.",
         {"timestamp": 0}),
        ("negative-timestamp", "signed-timestamp", "A negative timestamp is not positive.",
         {"timestamp": -TIMESTAMP}),
        ("string-timestamp", "signed-timestamp", "The signed timestamp is a JSON integer; BigInt would accept a decimal string, the profile does not.",
         {"timestamp": str(TIMESTAMP)}),
        ("numeric-rpc-address", "signed-fee-members", "rpc_address is null or a string, never a number.",
         {"transaction_fee": dict(SDK_FEES, rpc_address=0)}),
        ("string-nonce", "signed-nonce-integer",
         "demosdk signs a numeric nonce; the pinned node's consensus filter compares it with === and never applies a decimal string.",
         {"nonce": str(NONCE)}),
        # The edits name F = content.from, as an implementation that defaults
        # the missing member to the sender would regenerate them.
        ("ed25519-address-missing", "signed-ed25519-address",
         "sign() always adds from_ed25519_address and the SDK edit generator dereferences it; a send without it is never broadcast.",
         {"omit": ("from_ed25519_address",)}),
        ("ed25519-address-mismatch", "decode-address", "from_ed25519_address, the debited account, must project to the signing sender.",
         {"from_ed25519_address": "0x" + OTHER_KEY}),
        ("edits-missing", "signed-native-edits", "sign() always regenerates gcr_edits; the node refuses a send without them.",
         {"omit": ("gcr_edits",)}),
        ("edits-credit-differs", "signed-native-edits", "The node regenerates the edits and refuses a credit other than the send amount.",
         {"gcr_edits": [control_edits[0], dict(control_edits[1], amount=OTHER_AMOUNT_OS), *control_edits[2:]]}),
        ("edits-extra-credit", "signed-native-edits", "An extra credit edit is a forged mint; the regenerated edits differ.",
         {"gcr_edits": [*control_edits, dict(control_edits[1], account="0x" + PAYER_KEY)]}),
    ):
        omit = changes.pop("omit", ())
        vectors.append(gate("broadcast-signed-" + name, "fail", "DEM-1", [guard, "signed-transfer-matches-retention"], note,
                            **consistent(_apply(signed_body, changes), omit=omit)))
    vectors.append(gate("broadcast-dem-os-misconversion", "fail", "DEM-1",
                        ["retained-amount-is-phase-amount"], "1.5 DEM is 1500000000 OS, not 1500000001.",
                        **consistent(send_content(nonce=NONCE, amount=OTHER_AMOUNT_OS, amount_os=OTHER_AMOUNT_OS), amountOs=OTHER_AMOUNT_OS)))
    vectors.append(classify("confirmed-string-block-number", "indeterminate", unbound,
                            ["decode-block"] + unresolved, "blockNumber must be a JSON number, never a string.",
                            read=found(record("confirmed", blockNumber=str(BLOCK)))))
    for suffix, changes in (("missing", {}), ("empty", {"gcr_edits": []}), ("malformed", {"gcr_edits": {}})):
        read = found(record("confirmed", send_content(**changes), edits=_OMIT), applied=False)
        vectors.append(classify("confirmed-unproven-" + suffix + "-edits", "indeterminate", "DEM-3/DEM-5",
                                unresolved,
                                "Confirmed without the send's edits or an applied-payment authority proves no payment.", read=read))
        vectors.append(admit("consumer-unproven-" + suffix + "-edits", "indeterminate", "DEM-7",
                             ["consumer-requires-confirmed-record"],
                             "No send edits and no applied payee credit authority means no settlement.", read=read))
    vectors.append(deliver("delivery-confirmed-without-applied-payment", "indeterminate", "DEM-7/FV-5",
                           ["consumer-requires-confirmed-record", "delivery-requires-dem7", "success-requires-applied-transfer"],
                           "All other gates passing cannot authorize delivery without proof of applied payment, even with the send's edits.",
                           read=found(record("confirmed"), authenticated=True, applied=False),
                           dem7_passed=False))
    # Each member of the DEMOS-MAPPING §A.2 applied-payment binding, on the
    # handler (DEM-3) and the consumer (DEM-7) path.
    # A zero debit or credit is a committed transition that moved nothing on
    # that side, so the authority's figure is still its committed change.
    for suffix, changes, binding in (
        ("unauthenticated", {"appliedTransferAuthenticated": False}, []),
        ("zero-credit", dict(APPLIED, payeeAfterOs=PAYEE_PRE_STATE_OS), []),
        ("zero-debit", dict(APPLIED, payerAfterOs=os_difference(PAYER_PRE_STATE_OS, GAS_OS)), []),
        ("wrong-hash", {"txHash": OTHER_TX_HASH}, []),
        ("wrong-block", {"blockNumber": BLOCK + 1}, []),
        ("wrong-sender", {"sender": OTHER_KEY}, []),
        ("wrong-recipient", {"recipient": OTHER_KEY}, []),
        ("other-network", {"networkId": "demos:testnet"}, ["applied-transfer-binds-network"]),
        ("other-genesis", {"genesisHash": _hex("genesis:demos:other")}, ["applied-transfer-binds-network"]),
        ("other-block-id", {"blockId": _hex("block:other-at-" + str(BLOCK))}, ["applied-transfer-binds-block-id"]),
    ):
        read = found(record("confirmed"))
        if suffix == "unauthenticated":
            read.update(changes)
        elif suffix.startswith("zero-"):
            with_state(read, changes)
        else:
            read["appliedTransfer"].update(changes)
        vectors.append(classify("confirmed-applied-transfer-" + suffix, "indeterminate", "DEM-3/DEM-5",
                                ["success-requires-applied-transfer"] + binding + unresolved,
                                "Applied payment authority must authenticate this exact native send on the phase's network and inclusion block.",
                                read=read))
        vectors.append(admit("consumer-applied-transfer-" + suffix,
                             "indeterminate" if suffix == "unauthenticated" else "fail", "DEM-7/FV-5",
                             ["consumer-requires-confirmed-record", "success-requires-applied-transfer"] + binding
                             + ([] if suffix == "unauthenticated" else ["consumer-authenticated-contradiction-fails"]),
                             "Authenticated applied-payment contradictions refute settlement; unavailable authority is indeterminate.", read=read))
    # Two checks refuse it, so neither guard alone flips it: the
    # consumer-path twin below keeps the applied-authority witness.
    vectors.append(classify("confirmed-inclusion-without-block-id", "indeterminate", "DEM-3/DEM-5",
                            unresolved,
                            "Without the inclusion block's ID neither the applied-payment authority nor the "
                            "bft-final inclusion binds a block identity.",
                            read=found(record("confirmed")), inclusion={"blockNumber": BLOCK}))
    consumer_without_block_id = admit("consumer-inclusion-without-block-id", "indeterminate", "DEM-7",
                                      ["applied-transfer-binds-block-id", "consumer-requires-confirmed-record",
                                       "success-requires-applied-transfer"],
                                      "A consumer without the inclusion block's ID cannot bind the applied-payment authority.",
                                      read=found(record("confirmed")))
    consumer_without_block_id["protocolInput"]["inclusionObservation"] = {"blockNumber": BLOCK}
    vectors.append(consumer_without_block_id)
    # DEM-1 before signing: a binding that cannot reach DEM-3 success is a
    # permanent refusal, and nothing is signed.
    vectors += [
        pre_sign("sign-with-pinned-node-and-applied-payment-authority", "pass", ["sign-allowed-when-configured"],
                 "A binding that pins nodes, configures applied-payment authority and attests gasFeeSeparation unscheduled lets the handler sign."),
        pre_sign("sign-without-pinned-node", "fail", ["binding-refusal-is-rail-unavailable", "sign-requires-pinned-node"],
                 "Without a pinned node no record binds: ok false, substrate under RAV-R4, before pay() or sign().",
                 pinned_node=False),
        pre_sign("sign-without-applied-payment-authority", "fail",
                 ["binding-refusal-is-rail-unavailable", "sign-requires-applied-payment-authority"],
                 "Without applied-payment authority DEM-3 success is unreachable: ok false, substrate, nothing signed.",
                 applied_authority=False),
        pre_sign("sign-with-gas-fee-separation-scheduled", "fail",
                 ["binding-refusal-is-rail-unavailable", "sign-requires-gas-fee-separation-unscheduled"],
                 "A network whose genesis schedules gasFeeSeparation, at any height, stores fee edits no record profile admits.",
                 fee_separation_unscheduled=False),
        pre_sign("sign-without-fork-attestation", "fail",
                 ["binding-refusal-is-rail-unavailable", "sign-requires-gas-fee-separation-unscheduled"],
                 "RPC does not report gasFeeSeparation; a binding that attests nothing from genesis cannot sign.",
                 fee_separation_unscheduled=_OMIT),
        pre_sign("sign-without-binding", "fail", ["binding-refusal-is-rail-unavailable"],
                 "At settle, after the preflight passed, a missing binding is a rail that is not operational: "
                 "substrate (RAV-R4), never permanent, so the payer is not blamed after the payee delivered.",
                 binding=[]),
        # RAV-R3 for pay-dem: the binding is checked before the rail is
        # selected, whatever availability the RailDefinition shows.
        preflight("preflight-live-rail-with-binding", "pass", ["preflight-selects-configured-rail"],
                  "A live pay-dem rail whose payer binding holds all three DEM-1 members is selectable."),
        preflight("preflight-live-rail-without-applied-payment-authority", "fail",
                  ["pay-dem-preflight-whatever-availability", "preflight-requires-binding"],
                  "A live pay-dem RailDefinition does not show the binding: without an applied-payment authority the "
                  "rail is not selected, so no Agreement commits to a rail the payer cannot pay on.",
                  applied_authority=False),
        preflight("preflight-live-rail-without-fork-attestation", "fail",
                  ["pay-dem-preflight-whatever-availability", "preflight-requires-binding"],
                  "A binding that attests nothing from genesis about gasFeeSeparation fails the preflight on a live rail.",
                  fee_separation_unscheduled=_OMIT),
        preflight("preflight-operator-gated-rail-without-pinned-node", "fail", ["preflight-requires-binding"],
                  "RAV-R3 as written: an operator_gated pay-dem rail without pinned nodes is not selected.",
                  availability="operator_gated", pinned_node=False),
        preflight("preflight-operator-gated-rail-with-binding", "pass", ["preflight-selects-configured-rail"],
                  "An operator_gated pay-dem rail with the binding in place is selectable.",
                  availability="operator_gated"),
    ]
    # DEM-1/RAV-R3 "for the phase's network": the rail's network is the pinned
    # RailDefinition's consumerFinalityProfile.settlement network, never one
    # the binding supplies. The handler finds its binding entry by that
    # network, and each member must name it: pinned nodes or an authority for
    # another network, or a fork attestation from another genesis, let the
    # transfer execute where the record can never settle or bind.
    elsewhere = (
        ("binding-for-another-network", "A binding configured only for another network holds nothing for the rail's; "
         "a handler that keeps one global binding would sign and debit the payer there.",
         ["binding-network-is-rail-network"], {"binding": [binding_entry(OTHER_NETWORK)]}),
        ("binding-for-replaced-genesis", "A binding entry for the rail's network name over another sealed genesis is "
         "not the rail's network.",
         ["binding-network-is-rail-network"], {"binding": [binding_entry(OTHER_GENESIS)]}),
        ("pinned-nodes-for-another-network", "Nodes pinned for another network serve that network's records: the "
         "transfer would land where DEM-2 can never bind it.",
         ["pinned-nodes-bind-rail-network"], {"pinned_node": dict(OTHER_NETWORK)}),
        ("applied-authority-for-another-network", "An applied-payment authority for another network can never "
         "authenticate a payment on the rail's.",
         ["applied-authority-binds-rail-network"], {"applied_authority": dict(OTHER_NETWORK)}),
        ("fork-attestation-of-another-genesis", "An unscheduled gasFeeSeparation attested from another genesis says "
         "nothing about the rail's; if its genesis schedules the fork the payer is debited and nothing settles.",
         ["fork-attestation-binds-rail-genesis"], {"fee_separation_unscheduled": dict(OTHER_GENESIS, activationHeight=None)}),
    )
    member_guard = {
        "pinned-nodes-bind-rail-network": ("sign-requires-pinned-node", "broadcast-requires-pinned-node"),
        "applied-authority-binds-rail-network": ("sign-requires-applied-payment-authority",
                                                 "broadcast-requires-applied-payment-authority"),
        "fork-attestation-binds-rail-genesis": ("sign-requires-gas-fee-separation-unscheduled",
                                                "broadcast-requires-gas-fee-separation-unscheduled"),
    }
    for suffix, note, guards, changes in elsewhere:
        sign_guards = guards + [g for guard in guards for g in member_guard.get(guard, ())[:1]]
        egress_guards = guards + [g for guard in guards for g in member_guard.get(guard, ())[1:]]
        vectors += [
            pre_sign("sign-with-" + suffix, "fail", sign_guards + ["binding-refusal-is-rail-unavailable"], note,
                     **changes),
            gate("confirm-with-" + suffix, "fail", "DEM-1", egress_guards + ["retention-before-first-egress"], note,
                 request="confirm-retained", **changes),
            gate("broadcast-with-" + suffix, "fail", "DEM-1", egress_guards, note, **changes),
            preflight("preflight-live-rail-with-" + suffix, "fail",
                      guards + ["pay-dem-preflight-whatever-availability", "preflight-requires-binding"], note,
                      **changes),
        ]
    # The rail's entry is found by its network, not by position: a payer with
    # a binding per network signs on the rail's even when another comes first.
    several = [binding_entry(OTHER_NETWORK, appliedPaymentAuthority=_OMIT), binding_entry()]
    vectors += [
        pre_sign("sign-with-rail-network-entry-among-several", "pass",
                 ["binding-network-is-rail-network", "sign-allowed-when-configured"],
                 "The handler uses the entry for the rail's network; the first entry, for another network, is not it.",
                 binding=several),
        gate("broadcast-with-rail-network-entry-among-several", "pass", "DEM-1",
             ["binding-network-is-rail-network", "first-broadcast-allowed", "submission-completes-own-confirm"],
             "The broadcast gate reads the entry for the rail's network, wherever it stands in the binding.",
             binding=several),
        preflight("preflight-live-rail-with-rail-network-entry-among-several", "pass",
                  ["binding-network-is-rail-network", "preflight-selects-configured-rail"],
                  "The preflight finds the rail's entry by its network.", binding=several),
    ]
    # DEMOS-MAPPING §A.2 pay-dem party address: payee.payeeAddress and the
    # payer.payingKey key are a Demos key (optional 0x) or a DACS-1
    # did:demos:agent: DID; DEM-1, DEM-7 and FV-5 compare the 64 hex digits
    # they project to, and any other spelling is error.
    did = "did:demos:agent:"
    vectors += [
        gate("broadcast-to-0x-payee-address", "pass", "DEM-1", PARTY_GUARDS["gate"],
             "A 0x-prefixed payeeAddress, the node's own spelling, projects to the retained recipient.",
             phase_context=phase(payeeAddress="0x" + PAYEE_KEY)),
        gate("broadcast-to-did-payee-address", "pass", "DEM-1", PARTY_GUARDS["gate"],
             "A DACS-1 did:demos:agent: payout binding projects to its key component.",
             phase_context=phase(payeeAddress=did + PAYEE_KEY)),
        gate("broadcast-from-did-paying-key", "pass", "DEM-1", PARTY_GUARDS["gate"],
             "The Demos key of payer.payingKey is projected the same way.",
             phase_context=phase(payerPayingKey=did + PAYER_KEY)),
        gate("broadcast-payee-address-upper-case", "error", "DEM-1", PARTY_GUARDS["malformed"],
             "Upper-case hex is not a Demos key: the payee projects to nothing and nothing leaves.",
             phase_context=phase(payeeAddress="0x" + PAYEE_KEY.upper())),
        gate("broadcast-payee-address-did-with-0x", "error", "DEM-1", PARTY_GUARDS["malformed"],
             "A DID key component is 64 bare lower-case hex digits; did:demos:agent:0x... is no pay-dem address.",
             phase_context=phase(payeeAddress=did + "0x" + PAYEE_KEY)),
        gate("broadcast-payee-address-evm-length", "error", "DEM-1", PARTY_GUARDS["malformed"],
             "A 20-byte EVM address is not a Demos key.",
             phase_context=phase(payeeAddress="0x" + PAYEE_KEY[:40])),
        admit("consumer-0x-payee-address-passes", "pass", "DEM-7", PARTY_GUARDS["admit"],
              "DEM-7 binds the record's recipient to the projection of payeeAddress, not its spelling.",
              read=found(record("confirmed")), phase_context=phase(payeeAddress="0x" + PAYEE_KEY)),
        admit("consumer-did-payee-address-passes", "pass", "DEM-7", PARTY_GUARDS["admit"],
              "A did:demos:agent: payeeAddress binds the same recipient.",
              read=found(record("confirmed")), phase_context=phase(payeeAddress=did + PAYEE_KEY)),
        admit("consumer-payee-address-malformed", "error", "DEM-7", PARTY_GUARDS["malformed-admit"],
              "A payeeAddress in no pay-dem form binds nothing: error, never a comparison of spellings.",
              read=found(record("confirmed")), phase_context=phase(payeeAddress="0x" + PAYEE_KEY.upper())),
        deliver("delivery-to-0x-payee-address", "pass", "DEM-7/FV-5", PARTY_GUARDS["admit"],
                "A genuine payment to the payee's key authorizes delivery whichever pay-dem spelling the Agreement used.",
                phase_context=phase(payeeAddress="0x" + PAYEE_KEY)),
        deliver("delivery-to-did-payee-address", "pass", "DEM-7/FV-5", PARTY_GUARDS["admit"],
                "The DACS-1 primary-claim DID spelling of the payout binding delivers too.",
                phase_context=phase(payeeAddress=did + PAYEE_KEY)),
        deliver("delivery-from-0x-paying-key", "pass", "DEM-7/FV-5", PARTY_GUARDS["admit"],
                "A 0x-prefixed payer.payingKey key binds the same sender.",
                phase_context=phase(payerPayingKey="0x" + PAYER_KEY)),
    ]

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
        ("legacy-spelling-collision", dict(ref, txHash="0x" + TX_HASH.upper()), "indeterminate"),
    ):
        refs = [ref, second_ref]
        records = [{"jobId": job, "phaseIndex": PHASE_INDEX, "txRef": item} for job, item in zip((JOB_ID, OTHER_JOB_ID), refs)]
        if name == "legacy-spelling-collision":
            records[1]["legacy"] = True
        vectors.append(_vector("sb2-demos-" + name, "resolve-settlement-group", {"records": records, "consumerAdmissions": []},
                               expected,
                               {"records": [{"settlementTxId": "demos:" + item["txHash"].removeprefix("0x").lower(),
                                             "decision": expected} for item in refs]},
                               "DEM-7/SB-1/SB-2", [], "Derive keys before grouping; no job, block or legacy spelling may split one transfer."))
    # Settlement accounting and the DACS-5 derivation group the presented set
    # only: an earlier admission of the same hash for another job that is not
    # presented must not change the result, or a re-run of the derivation from
    # its own contents could not reproduce its metrics.
    vectors.append(_vector(
        "sb2-demos-unpresented-admission-not-added", "resolve-settlement-group",
        {"records": [{"jobId": OTHER_JOB_ID, "phaseIndex": PHASE_INDEX, "txRef": ref}],
         "consumerAdmissions": [{"jobId": JOB_ID, "phaseIndex": PHASE_INDEX, "txRef": ref}]},
        "pass", {"records": [{"settlementTxId": "demos:" + TX_HASH, "decision": "pass"}]},
        "DEM-7/SB-2", [],
        "Accounting over a presented set never adds the consumer's other admissions; only the payee's delivery check presents them."))
    # DEM-1 is checked at the first egress of the signed bytes, including the
    # demosdk confirm (confirmTx) request; DEM-6 starts there.
    vectors += [
        gate("confirm-after-durable-retention", "pass", "DEM-1", ["first-broadcast-allowed"],
             "The confirm request is the first egress: it may carry the signed transfer once it is durably retained.",
             request="confirm-retained"),
        gate("confirm-before-durable-retention", "fail", "DEM-1",
             ["broadcast-requires-durable-retention", "retention-before-first-egress"],
             "confirmTx hands the signed bytes to a node, which can submit them; retention must be durable first.",
             request="confirm-retained", durable=False),
        # The profile's only submission route is confirm, then the one
        # broadcast that completes it; every other call carrying the signed
        # bytes is refused, however well retained.
        gate("sr3-proxy-submission-refused", "fail", "DEM-1/DEM-6", ["egress-only-confirm-then-broadcast"],
             "pay-dem defines no SR-3 proxy submission: a durably retained, authentic transfer is still not sent that way.",
             request="sr3-proxy-submission"),
        gate("wallet-direct-submission-refused", "fail", "DEM-1/DEM-6", ["egress-only-confirm-then-broadcast"],
             "A wallet call that submits the signed bytes without confirm, such as an SDK helper, is not a profile route.",
             request="wallet-direct-submission"),
        gate("broadcast-completes-own-confirm", "pass", "DEM-1/DEM-6",
             ["first-broadcast-allowed", "submission-completes-own-confirm"],
             "The one broadcast that completes the uninterrupted submission whose confirm just returned, carrying that confirm's validity response.",
             broadcast_state="confirm-returned"),
        # demosdk broadcast(validationData) sends the confirm result, and the
        # pinned node executes the transaction embedded in it.
        gate("broadcast-validity-response-missing", "fail", "DEM-1/DEM-6",
             ["broadcast-carries-own-validity-response"],
             "A broadcast that carries no validity response sends nothing the handler retained.",
             carried_response=None),
        gate("broadcast-stale-validity-response", "fail", "DEM-1/DEM-6",
             ["broadcast-carries-own-validity-response"],
             "A validity response from an earlier confirm is not the one this submission's confirm returned.",
             carried_response=validity_response(signed(), reference_block=CONFIRM_REFERENCE_BLOCK - 4)),
        gate("broadcast-validity-response-other-transaction", "fail", "DEM-1/DEM-6",
             ["validity-response-binds-retained-transfer"],
             "The node executes the embedded transaction: a same-sender payment of another amount is not the retained transfer.",
             confirm_response=validity_response(signed(send_content(nonce=NONCE, amount=OTHER_AMOUNT_OS, amount_os=OTHER_AMOUNT_OS)))),
        gate("broadcast-validity-response-other-nonce", "fail", "DEM-1/DEM-6",
             ["validity-response-binds-retained-transfer"],
             "An embedded transfer with another nonce is another transaction, however it is signed.",
             confirm_response=validity_response(signed(send_content(nonce=NONCE + 1, amount=AMOUNT_OS)))),
        gate("broadcast-validity-response-not-valid", "fail", "DEM-1/DEM-6",
             ["validity-response-binds-retained-transfer"],
             "confirmTx answers result 200 with valid false when it refuses the transfer; that response completes nothing.",
             confirm_response=validity_response(signed(), valid=False)),
        gate("broadcast-validity-response-resigned-content", "fail", "DEM-1/DEM-6",
             ["validity-response-binds-retained-transfer"],
             "Embedded content re-serialized in another member order hashes differently from the retained signed bytes.",
             confirm_response=validity_response(dict(signed(), content=dict(reversed(list(signed()["content"].items())))))),
        gate("rebroadcast-after-interrupted-confirm-refused", "fail", "DEM-6",
             ["confirm-egress-may-broadcast", "no-rebroadcast"],
             "After a confirm timeout, error or restart the node may have submitted the bytes; only re-reads follow.",
             broadcast_state="confirm-sent-interrupted"),
        gate("replacement-after-interrupted-confirm-refused", "fail", "DEM-6",
             ["confirm-egress-may-broadcast", "no-replacement"],
             "A restart after confirm never signs a replacement transfer for the same phase.",
             broadcast_state="confirm-sent-interrupted", request="broadcast-replacement"),
        gate("broadcast-without-applied-payment-authority", "fail", "DEM-1",
             ["broadcast-requires-applied-payment-authority"],
             "Without applied-payment authority DEM-3 success is unreachable, so nothing is signed or sent.",
             applied_authority=False),
        gate("confirm-without-applied-payment-authority", "fail", "DEM-1",
             ["broadcast-requires-applied-payment-authority", "retention-before-first-egress"],
             "The binding precondition holds at the confirm request too.",
             applied_authority=False, request="confirm-retained"),
        gate("broadcast-without-pinned-node", "fail", "DEM-1", ["broadcast-requires-pinned-node"],
             "Without a pinned node no record binds, so nothing is signed or sent.",
             pinned_node=False),
        gate("broadcast-with-gas-fee-separation-scheduled", "fail", "DEM-1",
             ["broadcast-requires-gas-fee-separation-unscheduled"],
             "On a network whose genesis schedules gasFeeSeparation the transfer would execute but never settle.",
             fee_separation_unscheduled=False),
        gate("confirm-with-gas-fee-separation-scheduled", "fail", "DEM-1",
             ["broadcast-requires-gas-fee-separation-unscheduled", "retention-before-first-egress"],
             "The fork-scope precondition holds at the confirm request too.",
             fee_separation_unscheduled=False, request="confirm-retained"),
        gate("broadcast-without-fork-attestation", "fail", "DEM-1",
             ["broadcast-requires-gas-fee-separation-unscheduled"],
             "A binding that attests no gasFeeSeparation state from genesis sends nothing.",
             fee_separation_unscheduled=_OMIT),
        # DEM-6: a confirm is a call too; once the signed bytes may have left
        # the handler it is never repeated, whatever the last call returned.
        gate("confirm-after-interrupted-confirm-refused", "fail", "DEM-6",
             ["confirm-egress-may-broadcast", "no-rebroadcast", "retention-before-first-egress"],
             "A confirm that timed out, errored or was cut off by a restart is not sent again.",
             broadcast_state="confirm-sent-interrupted", request="confirm-retained"),
        gate("confirm-after-maybe-broadcast-refused", "fail", "DEM-6", ["no-rebroadcast", "retention-before-first-egress"],
             "Once the transfer may have been broadcast, a second confirm is a second call carrying it.",
             broadcast_state="maybe-broadcast", request="confirm-retained"),
        gate("confirm-after-confirm-returned-refused", "fail", "DEM-6", ["no-rebroadcast", "retention-before-first-egress"],
             "After this submission's confirm returned, only its own broadcast follows, never another confirm.",
             broadcast_state="confirm-returned", request="confirm-retained"),
        # DEM-6 after a restart: a crash can fall between a call carrying the
        # signed bytes and the journal entry that records it, so a transfer
        # retained before the (re)start is maybe-broadcast whatever was recorded.
        gate("confirm-after-restart-refused", "fail", "DEM-6",
             ["no-rebroadcast", "restart-is-maybe-broadcast", "retention-before-first-egress"],
             "A retained transfer still recorded as never-broadcast after a restart may have reached a node: no confirm.",
             broadcast_state="never-broadcast", request="confirm-retained", restarted=True),
        gate("replacement-after-restart-refused", "fail", "DEM-6",
             ["no-replacement", "restart-is-maybe-broadcast"],
             "After a restart the handler never sends a replacement for a retained transfer recorded as never-broadcast.",
             broadcast_state="never-broadcast", request="broadcast-replacement", restarted=True),
        gate("broadcast-after-restart-from-confirm-returned-refused", "fail", "DEM-6",
             ["no-rebroadcast", "restart-is-maybe-broadcast"],
             "A restart interrupts the submission: the confirm that returned before it is never completed by a broadcast.",
             broadcast_state="confirm-returned", request="broadcast-retained", restarted=True),
        gate("broadcast-gate-restart-unstated", "fail", "DEM-6",
             ["no-rebroadcast", "restart-is-maybe-broadcast", "retention-before-first-egress"],
             "A gate input that does not state false for the restart is a restart: fail closed.",
             broadcast_state="never-broadcast", request="confirm-retained", restarted=None),
        gate("broadcast-hash-uppercase", "fail", "DEM-1", ["signed-hash-form"],
             "The node compares the derived hash exactly, so an upper-case hash is refused even when signed as spelled.",
             signed_transaction=dict(signed(), hash=TX_HASH.upper(),
                                     signature={"type": "ed25519", "data": "0x" + PAYER_SIGNER.sign(TX_HASH.upper().encode()).hex()})),
        gate("broadcast-oversized-phase-amount", "fail", "DEM-1", ["retained-amount-is-phase-amount"],
             "The phase DEM amount converts to OS by spelling; an oversized amount is compared, not refused by int().",
             phase_context=phase(amount={"amount": OVERSIZED_OS, "currency": "DEM"}, amountOs=OVERSIZED_OS + "000000000")),
        classify("record-oversized-amount", "indeterminate", unbound, ["bind-amount"] + unresolved,
                 "An oversized OS amount decodes as a canonical string and is unbound; it never aborts the handler.",
                 read=found(record("confirmed", send_content(amount_os=OVERSIZED_OS, amount=OVERSIZED_OS)),
                            state=committed(amount_os=OVERSIZED_OS, payer_before=OVERSIZED_PAYER_OS))),
        classify("record-oversized-nonce", "indeterminate", unbound, ["bind-nonce"] + unresolved,
                 "An oversized nonce decodes as a canonical string and is unbound.",
                 read=found(record("confirmed", send_content(nonce=OVERSIZED_OS)))),
        classify("applied-transfer-oversized-debit", "indeterminate", "DEM-3/DEM-5",
                 ["success-requires-applied-transfer"] + unresolved,
                 "An applied debit other than the OS amount, however long, is no proof of payment.",
                 read=found(record("confirmed"), state=committed(amount_os=OVERSIZED_OS, payer_before=OVERSIZED_PAYER_OS))),
        admit("consumer-oversized-record-amount", "indeterminate", "DEM-7",
              ["consumer-binds-amount", "consumer-requires-confirmed-record"],
              "An oversized record amount is compared with the phase by spelling and does not bind.",
              read=found(record("confirmed", send_content(amount_os=OVERSIZED_OS, amount=OVERSIZED_OS)),
                         state=committed(amount_os=OVERSIZED_OS, payer_before=OVERSIZED_PAYER_OS))),
        admit("consumer-oversized-amount-bound", "pass", "DEM-7", ["consumer-admits-confirmed"],
              "A large amount that every source spells the same way still binds.",
              read=found(record("confirmed", send_content(amount_os=OVERSIZED_OS + "000000000", amount=OVERSIZED_OS + "000000000")),
                         state=committed(amount_os=OVERSIZED_OS + "000000000", payer_before=OVERSIZED_PAYER_OS)),
              phase_context=phase(amount={"amount": OVERSIZED_OS, "currency": "DEM"}, amountOs=OVERSIZED_OS + "000000000")),
    ]
    # A DEM-4 proof is APR closed-cannot-settle evidence only when it
    # carries FV-5's signed execution result for its failed record on the
    # rail's network and FV's bft-final inclusion of the transaction in the
    # block that result names (APR-6: authenticated inclusion and finality).
    # The APR check verifies both itself and never trusts the handler's word
    # or label.
    for name, expected, authentication, inclusion, guards, note in (
        ("apr-evidence-plain-rpc-failure-proof", "indeterminate", "rpc-read", _SERVED,
         ["apr-evidence-requires-authenticated-failure"],
         "The pin does not authenticate an RPC read, so a proof built on one authorizes no replacement job."),
        ("apr-evidence-authenticated-failure-proof", "pass", _OMIT, _SERVED,
         ["apr-evidence-from-authenticated-failure"],
         "The same failed record with FV-5's signed execution result and its verifying bft-final inclusion is reconciliation evidence."),
        *(
            ("apr-evidence-failure-proof-" + suffix, "indeterminate", authentication, _SERVED,
             ["apr-evidence-requires-authenticated-failure", guard], note + " No replacement job is authorized.")
            for suffix, guard, authentication, note in fv5_variants(record("failed"), proof=True)
        ),
        *(
            ("apr-evidence-failure-proof-" + suffix, "indeterminate", _OMIT, inclusion,
             ["apr-evidence-requires-authenticated-failure", *guards], note + " No replacement job is authorized.")
            for suffix, guards, inclusion, note in bft_final_variants()
        ),
    ):
        vectors.append(_vector(
            name, "apr-reconciliation-evidence",
            {"railNetwork": NETWORK, **FINALITY, "fv5Policy": FV5_POLICY, "retainedTransfer": retained(),
             "retainedFailureProof": failure_proof(authentication=authentication, inclusion=inclusion)},
            expected, {"reconciliationEvidence": expected == "pass"}, "DEM-4/FV-5", guards, note,
        ))
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
            vector["guards"] = sorted(
                ["sb1-demos-id"]
                + (["sb2-group-raw-references"] if vector["expected"] == "indeterminate" else [])
                + (["sb2-presented-set-only"] if vector["protocolInput"]["consumerAdmissions"] else [])
                + (["sb1-demos-shape"] if vector["name"].endswith("-legacy-spelling-collision") else [])
            )
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
            "status confirmed and independent applied-payment authority succeeds; a bound failed record authenticated under FV-5 "
            "at its bft-final inclusion is a permanent failure, and a plain RPC read of one is unresolved; "
            "anything else is a substrate result without a second broadcast. "
            "FV-5 authentication is FV-5's signed execution result itself (recordRead.executionResult, "
            "retainedFailureProof.authentication), which every operation verifies against fv5Policy "
            "with the settlement-finality reference's verifier; a flag or label decides nothing. "
            "A DEM-4 proven failure, its reuse on resume and APR evidence also need FV's bft-final "
            "verification of the transaction's inclusion (recordRead.inclusionProof, "
            "retainedFailureProof.inclusionProof) in the block that result names, which they verify "
            "with that reference's verify_transaction_inclusion against finalityProfile and finalityTrust. "
            "appliedTransferAuthenticated, nodeBuild.source and otherGates are abstract inputs that "
            "state an authentication result: this corpus pins the decisions over them, not the "
            "authentication itself."
        ),
        "demosProfile": {
            "profile": "DEMOS-MAPPING §A.2 native-send record profile",
            "nodeSource": "kynesyslabs/node@" + NODE_COMMIT + " (stabilisation)",
            "nodeBuild": PINNED_BUILD,
            "sdk": "@kynesyslabs/demosdk@4.0.16 sha512-nVhp1uC+tFGzhew9c8XIajTMmELopx7gd0joqqzDd2XyUuFDcqrda51NYqvX5C8+L3Xgnie/mRf7JRqZ7r3tHA==",
            "liveObservations": "node2-* vectors copy read-only node2.demos.sh getTxByHash responses of 2026-10-17; the node reported 61b8e75 with a dirty tree, so they are observations, not the source pin",
        },
        "fixtureVocabulary": {
            "statusIndex": "getTransactionStatus state for the retained hash (included, pending or unknown); never decisive",
            "railNetwork": "the rail's Demos network (networkId, genesisHash): the pinned RailDefinition's consumerFinalityProfile.settlement network, never one a Demos binding supplies (a Demos NetworkSpec is the bare kind demos). Applied-payment authority must name the same network; the pre-sign, broadcast and preflight gates find the payer's binding entry by it; a missing or malformed one binds nothing",
            "demosBinding": "the payer's Demos binding configuration: one entry per network (networkId, genesisHash) holding pinnedNodes and appliedPaymentAuthority, each naming the network and genesis it was configured for, and gasFeeSeparation, the sealed genesis's forks.gasFeeSeparation attestation (networkId, genesisHash, activationHeight). The gates use the entry whose network is railNetwork, wherever it stands; a member is held only when it names exactly railNetwork, and the attestation only with activationHeight null. A missing entry or member, a member for another network or genesis, a scheduled height and any other form are refused",
            "inclusionObservation": "block number and, when observed, block ID (blockId) that include the retained hash or the signed txRef, or null; applied-payment authority must name the same block ID, and without one it binds no block identity",
            "recordRead": "getTxByHash read: found (record and nodeBuild), not-found or unavailable; appliedTransfer (networkId, genesisHash, blockId, txHash, blockNumber, sender, recipient, payerDebitOs, payeeCreditOs, committedBalances: payerBeforeOs, payerAfterOs, payeeBeforeOs, payeeAfterOs, feeOs) and appliedTransferAuthenticated model separate authenticated committed state-transition authority, never derived from the record's status, amount or edits; payerDebitOs must be payerBeforeOs - payerAfterOs - feeOs and payeeCreditOs must be payeeAfterOs - payeeBeforeOs, or the authority establishes nothing; the fixtures take the committed balances from the scenario's own pre-state and outcome (applied, rolled-back or no-op)",
            "nodeBuild": "the build attestation the Demos binding configuration holds for the node that served the read (source binding-attestation, commit, tree); only binding-attestation of commit 61b8e75aa8db5e408c49e1c3a89db4d673f45578 with a clean tree is pinned, and a self-reported build, another commit or a dirty tree is not",
            "gcr_edits": "a confirmed record establishes success only when its gcr_edits, each txhash blanked, are the four edits of its send; the pinned node applies a missing or empty list as a successful no-op",
            "otherGates": "verdicts of the FV, SB-1 and PB checks that compose with DEM-7 before delivery",
            "request": "the call about to carry the signed transaction out of the handler: confirm-retained (demosdk confirm/confirmTx, which carries signedTransaction), broadcast-retained or broadcast-replacement (demosdk broadcast, which carries validityResponse); these are the profile's only submission route, and any other value is refused, including sr3-proxy-submission and wallet-direct-submission",
            "signPermitted": "pre-sign-gate result, DEM-1 before demosdk pay()/sign(): the input holds no signed transaction; false with ok false and errorClass substrate (RAV-R4: the preflight passed, so the rail is not operational for this payer) is the handler's PC-4 result, and nothing is signed or sent",
            "broadcastState": "never-broadcast (nothing has left the handler), confirm-returned (this uninterrupted submission's confirm just returned), confirm-sent-interrupted (a confirm was sent, then a timeout, error or restart) or maybe-broadcast; any other value is refused",
            "confirmResponse": "the demosdk 4.0.16 confirm() result (RPCResponseWithValidityData) that the current submission's confirm returned to the handler, even late, or null; null for a confirm request",
            "validityResponse": "what the demosdk broadcast(validationData) call carries, or null for a confirm request; the pinned node executes its response.data.transaction, so it must be exactly confirmResponse, with result 200, valid true and an embedded transaction whose content, hash and signature serialize as signedTransaction",
            "payeeAddress": "phase member: payee.payeeAddress (and payerPayingKey the key payer.payingKey names), a DEMOS-MAPPING §A.2 pay-dem party address: a Demos key with optional 0x or a did:demos:agent: DID over 64 lower-case hex digits; DEM-1, DEM-7 and FV-5 compare the 64 digits it projects to, and any other value is error",
            "availability": "rail-preflight: the pinned pay-dem RailDefinition's availability for a new production session; disabled, failed and mocked are not selectable, any other unknown value is error, and every other value still needs the payer binding's three DEM-1 members for railNetwork (RAV-R3, whatever the availability)",
            "railSelectable": "rail-preflight want member: whether the orchestrator may select the rail, before Agreement signature and the PIPE-6 commitment",
            "fv5Policy": "the FV-5 independent execution-result policy the verifier trusts, from its own configuration: the settlement-finality corpus's fixture-independent-results-v1 kind, authorityKeys (base64url Ed25519) and threshold; a missing or malformed policy authenticates nothing",
            "executionResult": "recordRead member: FV-5's signed execution result for the record (kind, networkId, genesisHash, blockId, transactionRef, record, attestations, and the optional appliedTransfer: txHash, blockNumber, sender, recipient, payerDebitOs, payeeCreditOs, committedBalances), as the settlement-finality corpus signs it over the FV domain. It authenticates the record only when at least the policy's threshold of distinct policy keys verify it, it names railNetwork and the inclusion observation's blockId, its transactionRef is the record's own (kind demos, hash, blockNumber), its record serializes exactly as the record read, and a carried appliedTransfer is the change of its committedBalances, names the record's transaction, block and parties, and moves the record's OS amount when confirmed and nothing when failed. A handler's DEM-4 failure, a consumer's DEM-7 failed refutation or contradiction, and delivery need it; a plain RPC read has none",
            "inclusionProof": "recordRead and retainedFailureProof member: FV's bft-final inclusion observation of the record's transaction (networkId, genesisHash, transactionRef, transactionInclusionProof, inclusionBlock, authenticatedHead, ancestryProof, authorityEvidence, finalityCertificate) in the settlement-finality corpus's fixture codecs, whose raw transaction body is the native-send form (networkId, genesisHash, transactionRef, txHash, optional eventsRoot). every final verdict needs it to verify under finalityProfile and finalityTrust: DEM-4's other half (for the failed record's own reference, its inclusionBlock.id the blockId the verifying signed result names), DEM-3 success (for the retained txHash at the observed block, its inclusionBlock.id the observation's blockId), and DEM-7's fail and delivery (for the signed txRef, in the block the signed result names, or the observed block without one). Missing, unfinalized, under a forged certificate, absent from the block, off the authenticated head or of another block, it proves nothing and the verdict is indeterminate",
            "finalityProfile": "the rail's signed consumerFinalityProfile.settlement ChainFinalityProfile (kind bft-final, networkId and genesisHash of railNetwork, observation, validatorSetRef, quorumNumerator, quorumDenominator); one of another kind or network verifies nothing",
            "finalityTrust": "the verifier's own trust for that profile: validatorSets (by content hash), observationAuthorityKeys (base64url Ed25519) and verificationTimeMs, its local clock",
            "authenticated": "recordRead member of an earlier draft: a read that says it is FV-5-authenticated. It decides nothing, whoever sets it; the *-fv5-flag-only vectors pin that",
            "retainedFailureProof": "the DEM-4 proof the handler retained: classification, authentication (FV-5's signed execution result for the proof's own record, stored verbatim; rpc-read for a plain read, and the earlier draft's fv5-bft-final label, are none), inclusionProof (FV's bft-final inclusion observation, stored verbatim), inclusionBlock and the record. A resume and an APR check each verify both themselves, the result against fv5Policy and railNetwork and the inclusion against finalityProfile and finalityTrust in the block the result names (the proof has no inclusion observation of its own); a resume reuses only a proof that verifies and still binds, and APR accepts only such a proof. A retained proof means the phase ended: a resume whose proof does not verify re-reads, and that post-terminal re-read can prove the failure again but is never pass",
            "restartedSinceRetention": "false only when the handler has run without a restart since it retained the transfer; after a (re)start a retained transfer is maybe-broadcast whatever broadcastState was recorded, and anything but false is a restart. The handler derives it, and broadcastState and retentionDurable, from the journal it reads back from stable storage (the start that wrote the retention against its own, 128 random bits the handler draws for each start, which needs no stored state, so no loss or rollback of its store repeats it, and never takes from its caller), never from process-local state; tests/test_pay_dem_crash_restart.py stops a storage-backed reference handler on both sides of every transition and witnesses that derivation",
            "signedTransaction": "the signed transaction itself as the DEM-1 retention holds it, read back from the journal: a confirm request carries these bytes, and a broadcast's validity response must embed them",
            "hashRetainedForOtherPhases": "the other (jobId, phaseIndex) whose stored journals retain the same hash, read from storage like restartedSinceRetention; any entry refuses the egress",
            "call": "classify-egress-outcome: the handler's own step that returned, pre-egress-check (its balance read before any confirm or broadcast carried the signed bytes), confirm or broadcast; any other value may have carried the bytes",
            "outcome": "classify-egress-outcome: what that step returned: insufficient-balance, refused-not-valid (demosdk confirm()/broadcast() valid false), refused-by-dem1 (the handler's own refusal of the completing broadcast), transport-error, timeout, accepted, or anything else (unrecognized). Only insufficient-balance found by a pre-egress-check on an un-restarted journal recording never-broadcast is permanent; every other outcome is substrate with the retained hash kept and no further call, never transient",
            "cause": "classify-egress-outcome want member: call:outcome, so the result keeps the step and reply that produced it",
            "consumerAdmissions": "raw txRef, (jobId, phaseIndex) and legacy (verified legacy evidence) of pay-dem records the consumer admitted earlier. For admit-for-delivery they are the payee's own admissions, which its delivery check presents with the evidence: derive SB-1 IDs, collapsing legacy spellings, before grouping; an admitted reference without an SB-1 ID is error. For resolve-settlement-group they lie outside the presented records, and settlement accounting and the DACS-5 derivation never add them",
            "admissionIndex": "admit-for-delivery: the snapshot (revision, admissions) of the payee's durable admission index read for this check. consumerAdmissions must equal its admissions as a multiset of exact JCS bytes; a missing or malformed snapshot, or a presented history that omits or adds an admission, is error and authorizes no delivery. The payee adds this phase's admission with a write conditional on that revision",
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
