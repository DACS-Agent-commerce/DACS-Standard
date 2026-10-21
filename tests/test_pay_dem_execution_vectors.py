"""Execute the DACS-4 §9.5.9 DEM-1..DEM-7 pay-dem execution corpus."""

from __future__ import annotations

import base64
from decimal import ROUND_DOWN, Decimal, InvalidOperation, localcontext
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_pay_dem_execution_vectors as generator  # noqa: E402
from jcs import canonicalize  # noqa: E402
from demos_json import stringify  # noqa: E402
from settlement_finality_reference import (  # noqa: E402
    DEMOS_RECORD_PROFILE, _demos_committed_change, _demos_native_send, _demos_send_edits_match,
    _verify_demos_execution, _verify_demos_record, bft_final_trust, demos_applied_transfer_binds_record, demos_execution_policy, verify_transaction_inclusion,
)


VECTORS = ROOT / "conformance/vectors/security/pay-dem-execution-v0.1.json"
GENERATOR = ROOT / "scripts/generate_pay_dem_execution_vectors.py"
SPEC = ROOT / "spec/DACS-4-SETTLE.md"
DEMOS = ROOT / "spec/DEMOS-MAPPING.md"
WORKFLOW = ROOT / ".github/workflows/validate.yml"

# Each guard is one check of the oracle below. Disabling a guard models the
# corresponding wrong implementation; every vector names the guards whose
# removal must change its result.
GUARDS = frozenset({
    # DEM-1
    "sign-allowed-when-configured",
    # DEM-1: an unprojectable party address is refused before signing
    "pre-sign-party-address-projects",
    # DEM-1: a paying key that is no controlled Demos key claim is refused before signing and at every egress
    "pre-sign-paying-key-controlled",
    "broadcast-paying-key-controlled",
    "sign-requires-pinned-node",
    "sign-requires-applied-payment-authority",
    "sign-requires-gas-fee-separation-unscheduled",
    # DEM-1: every input DEM-3 and DEM-4 consume, before anything is signed
    "sign-requires-bft-final-trust",
    "sign-requires-execution-result-policy",
    "binding-refusal-is-rail-unavailable",
    # DEM-1: trust counts only when the FV verifier's own check passes it
    "bft-final-trust-verifies-profile",
    # DEM-1/RAV-R3 "for the phase's network": the rail's pinned network
    "binding-network-is-rail-network",
    "pinned-nodes-bind-rail-network",
    "applied-authority-binds-rail-network",
    "fork-attestation-binds-rail-genesis",
    "bft-final-trust-binds-rail-network",
    "execution-policy-binds-rail-network",
    # RAV-R3 for pay-dem, before rail selection
    "preflight-requires-binding",
    "preflight-selects-configured-rail",
    "preflight-requires-controlled-key-claim",
    "pay-dem-preflight-whatever-availability",
    # DEMOS-MAPPING §A.2 pay-dem party address
    "phase-party-address-projects",
    "first-broadcast-allowed",
    "retention-before-first-egress",
    "egress-only-confirm-then-broadcast",
    "broadcast-requires-pinned-node",
    "broadcast-requires-applied-payment-authority",
    "broadcast-requires-gas-fee-separation-unscheduled",
    "broadcast-requires-bft-final-trust",
    "broadcast-requires-execution-result-policy",
    "broadcast-requires-durable-retention",
    "broadcast-requires-complete-retention",
    "retention-bound-to-phase",
    "retained-sender-is-payer",
    "retained-recipient-is-payee",
    "retained-amount-is-phase-amount",
    "signed-transfer-matches-retention",
    "signed-transaction-authentic",
    "signed-hash-form",
    "signed-signature-form",
    "signed-os-strings",
    "signed-fee-members",
    "signed-timestamp",
    "signed-ed25519-address",
    "signed-native-edits",
    "signed-nonce-integer",
    "signed-nonce-compares-by-value",
    "no-cross-phase-reuse",
    # DEM-2 and the DEMOS-MAPPING §A.2 native-send record profile
    "node-build-attested",
    "claim-reference-parameters-ignored",
    "consumer-fv5-record-binds-without-node-pin",
    "consumer-fv5-edit-members-compare-by-name",
    "node-build-commit",
    "node-build-clean-tree",
    "decode-hash",
    "decode-block",
    "decode-nonce",
    "decode-amount",
    "decode-address",
    "decode-type",
    "decode-native-send",
    "bind-hash",
    "bind-nonce",
    "bind-block",
    "bind-sender",
    "bind-recipient",
    "bind-amount",
    "bind-requires-inclusion",
    # DEM-3
    "success-branch",
    "success-authorizes-no-delivery",
    "success-requires-record",
    "success-requires-exact-confirmed",
    "success-requires-applied-transfer",
    "confirmed-requires-send-edits",
    "applied-transfer-is-committed-change",
    "applied-transfer-binds-network",
    "applied-transfer-binds-block-id",
    # DEM-4
    "failure-is-permanent",
    "failure-requires-binding",
    "failure-requires-authentication",
    "failure-proof-retained",
    "resume-reuses-failure-proof",
    "resume-validates-failure-proof",
    "resume-requires-authenticated-proof",
    # DEM-6: a phase with a retained DEM-4 result has ended; a re-read after
    # its proof stops verifying is post-terminal and never a success
    "terminal-never-reopens",
    "apr-evidence-requires-authenticated-failure",
    "apr-evidence-from-authenticated-failure",
    # DEM-4 and DEM-7 under FV-5: the signed execution result itself
    "fv5-authentication-is-a-signed-result",
    "fv5-result-signed",
    "fv5-result-binds-rail-network",
    "fv5-result-binds-block-id",
    "fv5-result-binds-record",
    "fv5-result-applied-transfer-binds-record",
    # DEM-7: a consumer's signed result names the presented txRef
    "fv5-result-binds-signed-reference",
    # DEM-4's other half: FV's bft-final verification of the transaction's
    # inclusion in the block the signed result names
    "failure-requires-bft-final-inclusion",
    "bft-final-inclusion-verified",
    "bft-final-inclusion-binds-result-block",
    # The same bft-final inclusion for every other final verdict: DEM-3
    # success (PC-7), DEM-7's refutation and delivery
    "success-requires-bft-final-inclusion",
    "consumer-refutation-requires-bft-final-inclusion",
    "consumer-contradiction-requires-bft-final-inclusion",
    "delivery-requires-bft-final-inclusion",
    # A consumer verdict takes FV's own verdict on the presented reference's
    # bft-final inclusion when it is fail or error, as the
    # settlement-finality corpus scores the same input
    "consumer-takes-fv-inclusion-verdict",
    # DEM-5
    "unresolved-authorizes-nothing",
    # DEM-5/DEM-6 once the handler's own check or call returns (PC-4 pay-dem rows)
    "pre-egress-refusal-is-permanent",
    "post-egress-refusal-is-unresolved",
    "call-error-is-unresolved",
    # DEM-6
    "no-rebroadcast",
    "no-replacement",
    "restart-is-maybe-broadcast",
    "confirm-egress-may-broadcast",
    "submission-completes-own-confirm",
    "broadcast-carries-own-validity-response",
    "validity-response-binds-retained-transfer",
    # DEM-7
    "consumer-admits-confirmed",
    "consumer-requires-confirmed-record",
    "consumer-binds-hash",
    "consumer-binds-block",
    "consumer-binds-payer",
    "consumer-binds-controlled-claims-only",
    "claims-are-claim-references",
    "control-is-the-schemes-mechanism",
    "consumer-claims-before-fv-inclusion-verdict",
    "consumer-binds-payee",
    "consumer-binds-amount",
    "consumer-failed-refutes",
    "consumer-failed-requires-authentication",
    "consumer-authenticated-contradiction-fails",
    # DEM-7 composed with FV-5, SB-1, SB-2 and PB before delivery
    "delivery-requires-dem7",
    "delivery-requires-authenticated-record",
    "delivery-requires-sb1",
    "delivery-requires-pb",
    "delivery-sb2-own-admissions",
    "delivery-requires-admission-index",
    "delivery-admission-entries-validated",
    "delivery-history-is-admission-index",
    "sb2-admitted-malformed-error",
    "sb2-same-tuple-idempotent",
    "sb1-demos-id",
    "sb1-demos-canonical",
    "sb1-demos-shape",
    "sb2-group-raw-references",
    "sb2-presented-set-only",
})

# The expected PC-4 result of each handler class, written out here rather
# than taken from the generator.
HANDLER_WANT = {
    "pass": {
        "ok": True, "errorClass": None, "executionState": "executed",
        "evidence": "success-bft-final", "nextAction": "anchor-success-evidence",
        "onPauseExpiry": None, "retainedHashKept": True,
        "terminalFailureProofRetained": False, "deliveryAuthorized": False,
        "settlementAccounting": False, "broadcastPermitted": False,
        "replacementPermitted": False,
    },
    "fail": {
        "ok": False, "errorClass": "permanent", "executionState": "failed",
        "evidence": "failure-without-settlement-finality", "nextAction": "terminal-failure",
        "onPauseExpiry": None, "retainedHashKept": True,
        "terminalFailureProofRetained": True, "deliveryAuthorized": False,
        "settlementAccounting": False, "broadcastPermitted": False,
        "replacementPermitted": False,
    },
    "indeterminate": {
        "ok": False, "errorClass": "substrate", "executionState": "indeterminate",
        "evidence": "none", "nextAction": "st7-pause-re-read-retained-hash",
        "onPauseExpiry": "failed-substrate-without-replacement", "retainedHashKept": True,
        "terminalFailureProofRetained": False, "deliveryAuthorized": False,
        "settlementAccounting": False, "broadcastPermitted": False,
        "replacementPermitted": False,
    },
}
# A refusal before the first egress: nothing has carried the signed bytes, so
# no node holds them and the phase ends permanent (§9.5.9 failure modes).
NOT_SENT_WANT = {
    "ok": False, "errorClass": "permanent", "executionState": "not-sent",
    "evidence": "none", "nextAction": "terminal-failure",
    "onPauseExpiry": None, "retainedHashKept": True,
    "terminalFailureProofRetained": False, "deliveryAuthorized": False,
    "settlementAccounting": False, "broadcastPermitted": False,
    "replacementPermitted": False,
}

SAFE_MAX = 2**53 - 1
_ABSENT = object()
HASH = re.compile(r"[0-9a-f]{64}")
ADDRESS = re.compile(r"(?:0x)?([0-9a-f]{64})")
# DEMOS-MAPPING §A.2 pay-dem party address: a Demos key, or a DACS-1
# `did:demos:agent:` DID whose key component is 64 lower-case hex digits.
PARTY_ADDRESS = re.compile(r"(?:0x|did:demos:agent:|key:)?([0-9a-f]{64})")
# A `key:` or `did:demos:agent:` spelling is a ClaimReference, so DACS-1
# §6.3.1 has a reader ignore a `?<parameters>` suffix on it; bare and `0x`
# hex are not ClaimReferences and take none.
PARTY_CLAIM_PARAMETERS = re.compile(r"(?:did:demos:agent:|key:)([0-9a-f]{64})\?.*", re.DOTALL)
# A Demos key claim of a party's bundle is a DACS-1 ClaimReference: bare and
# 0x hex are address spellings, not claims (DEMOS-MAPPING §A.2).
# Its identity is `(scheme, identifier)`; a `?<parameters>` suffix is ignored.
DEMOS_KEY_CLAIM = re.compile(r"(key|did:demos:agent):([0-9a-f]{64})(?:\?.*)?", re.DOTALL)
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)")
SIGNATURE = re.compile(r"0x[0-9a-f]{128}")
RETAINED = {"jobId", "phaseIndex", "txHash", "nonce", "sender", "recipient", "amountOs"}
# DEMOS-MAPPING §A.2 applied-payment authority: network, inclusion block
# identity, transaction, parties, and the committed debit and credit.
APPLIED_TRANSFER = frozenset({
    "networkId", "genesisHash", "blockId", "txHash", "blockNumber", "sender", "recipient",
    "payerDebitOs", "payeeCreditOs", "committedBalances",
})
# The committed balance transition the authority authenticates: each party's
# balance before and after the transaction's apply, and the fee it charged.
COMMITTED_BALANCES = frozenset({"payerBeforeOs", "payerAfterOs", "payeeBeforeOs", "payeeAfterOs", "feeOs"})
NETWORK = frozenset({"networkId", "genesisHash"})
# DEMOS-MAPPING §A.2 node pin, written out here rather than taken from the
# generator: the binding's own attestation of the exact commit, clean tree.
PINNED_BUILD = {
    "source": "binding-attestation",
    "commit": "61b8e75aa8db5e408c49e1c3a89db4d673f45578",
    "tree": "clean",
}
REQUESTS = frozenset({"confirm-retained", "broadcast-retained", "broadcast-replacement"})
FEE_AMOUNTS = ("network_fee", "rpc_fee", "additional_fee")
# The pinned node's RPC ingress rebuilds the fee object in this order before
# it re-derives the hash (src/forks/serializerGate.ts).
FEE_MEMBERS = [*FEE_AMOUNTS, "rpc_address"]
GAS_OS = "1000000000"  # demosdk 4.0.16 gas edit: 1 DEM, serialized in OS


def regenerated_edits(content, off=frozenset()):
    """The native-send `gcr_edits` the pinned node regenerates at admission
    (demosdk 4.0.16 GCRGeneration, serialized post-fork), or None."""
    data = content.get("data")
    sender = content.get("from_ed25519_address")
    if sender is None and "signed-ed25519-address" in off:
        # The wrong implementation defaults the debited account to the sender.
        sender = content.get("from")
    if not (isinstance(data, list) and len(data) == 2 and isinstance(data[1], dict)
            and isinstance(data[1].get("args"), list) and len(data[1]["args"]) == 2
            and isinstance(data[1]["args"][0], str) and isinstance(sender, str)):
        return None
    to, amount = data[1]["args"]
    to = to if to.startswith("0x") else "0x" + to
    amount = amount if isinstance(amount, str) else str(amount)
    return [
        {"type": "balance", "operation": "remove", "isRollback": False, "account": sender, "txhash": "", "amount": amount},
        {"type": "balance", "operation": "add", "isRollback": False, "account": to, "txhash": "", "amount": amount},
        {"type": "balance", "account": sender, "operation": "remove", "amount": GAS_OS, "txhash": "", "isRollback": False},
        {"type": "nonce", "operation": "add", "account": sender, "amount": 1, "txhash": "", "isRollback": False},
    ]


def edits_match(content, off=frozenset()) -> bool:
    """The node blanks each `txhash` and compares the serialized lists."""
    edits, expected = content.get("gcr_edits"), regenerated_edits(content, off)
    if expected is None or not (isinstance(edits, list) and all(isinstance(e, dict) for e in edits)):
        return False
    try:
        return stringify([{**edit, "txhash": ""} for edit in edits]) == stringify(expected)
    except (ValueError, TypeError, UnicodeError):
        return False


def _os_difference(left: str, right: str) -> str | None:
    """Exact difference of two canonical OS decimals, or None when negative.
    Decimal arithmetic decides spellings past int()'s digit limit too."""
    with localcontext() as context:
        context.prec = max(len(left), len(right)) + 1
        value = Decimal(left) - Decimal(right)
    return None if value < 0 else format(value, "f")


def committed_change(proof) -> tuple[str, str] | None:
    """The payment debit (fee excluded) and payee credit that an authority's
    committed balances show, or None when they do not decode. The record's
    amount and edits play no part: they are the claim being checked."""
    balances = proof.get("committedBalances") if isinstance(proof, dict) else None
    if not (isinstance(balances, dict) and set(balances) == COMMITTED_BALANCES
            and all(isinstance(value, str) and DECIMAL.fullmatch(value) for value in balances.values())):
        return None
    payer = _os_difference(balances["payerBeforeOs"], balances["payerAfterOs"])
    debit = None if payer is None else _os_difference(payer, balances["feeOs"])
    credit = _os_difference(balances["payeeAfterOs"], balances["payeeBeforeOs"])
    return None if debit is None or credit is None else (debit, credit)


def _safe_integer(value) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value == int(value)
        and 0 <= value <= SAFE_MAX
    )


def _lenient_integer(value):
    """A permissive implementation: coerce whatever looks numeric."""
    try:
        if isinstance(value, (bool, int, float)):
            return int(value)
        return int(Decimal(str(value).strip()))
    except (InvalidOperation, ValueError, TypeError):
        return None


def _lenient_spelling(value):
    """The same permissive coercion, spelled as a decimal without int(), so an
    oversized value is compared instead of raising."""
    try:
        number = Decimal(int(value)) if isinstance(value, (bool, int, float)) else Decimal(str(value).strip())
        if not number.is_finite():
            return None
        whole = number.to_integral_value(rounding=ROUND_DOWN)
        return "0" if whole == 0 else format(whole, "f")
    except (InvalidOperation, ValueError, TypeError, OverflowError):
        return None


def _canonical(value):
    """A canonical decimal string, else None. Untrusted decimals are compared
    by this spelling and never converted with int()."""
    return value if isinstance(value, str) and DECIMAL.fullmatch(value) else None


def _integer(value, guard, off):
    """Profile integer: a safe JSON integer or a canonical decimal string,
    projected to its canonical spelling."""
    if guard in off:
        return _lenient_spelling(value)
    if _safe_integer(value):
        return str(int(value))
    return _canonical(value)


def _retained(transfer, field):
    """A DEM-1 retained value in its projected form: the nonce is a safe JSON
    integer and the OS amount a canonical decimal string."""
    value = transfer.get(field)
    if field == "nonce":
        return str(value) if _safe_integer(value) and isinstance(value, int) else None
    if field == "amountOs":
        return _canonical(value)
    return value


def _address(value, off):
    if "decode-address" in off:
        return value.strip().lower().removeprefix("0x") if isinstance(value, str) else None
    match = ADDRESS.fullmatch(value) if isinstance(value, str) else None
    return match.group(1) if match else None


def decode(transaction, off, *, executed: bool = True):
    """DEMOS-MAPPING §A.2 native-send projection of a node record (or, with
    ``executed=False``, of a signed transaction), or None."""
    if not isinstance(transaction, dict) or not isinstance(transaction.get("content"), dict):
        return None
    content = transaction["content"]
    projection = {}
    tx_hash = transaction.get("hash")
    if "decode-hash" in off or (not executed and "signed-hash-form" in off):
        tx_hash = tx_hash.lower().removeprefix("0x") if isinstance(tx_hash, str) else None
    elif not (isinstance(tx_hash, str) and HASH.fullmatch(tx_hash)):
        return None
    projection["txHash"] = tx_hash
    if executed:
        block = transaction.get("blockNumber")
        if "decode-block" in off:
            block = _lenient_integer(block)
        if not _safe_integer(block):
            return None
        if not isinstance(transaction.get("status"), str):
            return None
        projection["blockNumber"] = int(block)
        projection["status"] = transaction["status"]
    if "nonce" in content or "decode-nonce" not in off:
        nonce = _integer(content.get("nonce"), "decode-nonce", off)
        if nonce is None:
            return None
        projection["nonce"] = nonce
    amount = _integer(content.get("amount"), "decode-amount", off)
    sender = _address(content.get("from"), off)
    recipient = _address(content.get("to"), off)
    if amount is None or sender is None or recipient is None:
        return None
    fee = content.get("transaction_fee")
    if not executed and "signed-os-strings" not in off:
        if not (isinstance(content.get("amount"), str) and DECIMAL.fullmatch(content["amount"])
                and isinstance(fee, dict)
                and all(isinstance(fee.get(k), str) and DECIMAL.fullmatch(fee[k])
                        for k in FEE_AMOUNTS)):
            return None
    if (not executed and "signed-fee-members" not in off and isinstance(fee, dict)
            and all(k in fee for k in FEE_AMOUNTS)
            and (list(fee) != FEE_MEMBERS or not (fee["rpc_address"] is None or isinstance(fee["rpc_address"], str)))):
        return None
    if not executed and "signed-nonce-integer" not in off:
        # demosdk signs a JSON integer nonce; the pinned node never applies a string.
        nonce = content.get("nonce")
        # JSON numbers compare by value (DEMOS-MAPPING §A.2 *Decoding*): `9.0`
        # is the integer 9, which JSON.stringify signs as `9`. The wrong
        # implementation takes only a host integer type.
        if not _safe_integer(nonce) or ("signed-nonce-compares-by-value" in off and not isinstance(nonce, int)):
            return None
    if not executed and "signed-timestamp" not in off:
        timestamp = content.get("timestamp")
        if not (_safe_integer(timestamp) and timestamp > 0):
            return None
    if not executed and "signed-ed25519-address" not in off and "from_ed25519_address" not in content:
        return None
    if not executed and "signed-native-edits" not in off and not edits_match(content, off):
        return None
    if "from_ed25519_address" in content and "decode-address" not in off:
        if _address(content["from_ed25519_address"], off) != sender:
            return None
    if "decode-type" not in off and content.get("type") != "native":
        return None
    if "decode-native-send" not in off:
        data = content.get("data")
        if not (
            isinstance(data, list)
            and len(data) == 2
            and data[0] == "native"
            and isinstance(data[1], dict)
            and set(data[1]) == {"nativeOperation", "args"}
            and data[1]["nativeOperation"] == "send"
            and isinstance(data[1]["args"], list)
            and len(data[1]["args"]) == 2
            and _address(data[1]["args"][0], off) == recipient
            and _canonical(data[1]["args"][1]) == amount
        ):
            return None
    projection.update(sender=sender, recipient=recipient, amountOs=amount)
    return projection


def authentic(transaction, off=frozenset()) -> bool:
    """DEMOS-MAPPING §A.2 signed transaction: the demosdk 4.0.16 `hash` is the
    SHA-256 of `JSON.stringify(content)` and the ed25519 signature by
    `content.from` covers the UTF-8 hash."""
    if not isinstance(transaction, dict) or not isinstance(transaction.get("content"), dict):
        return False
    try:
        serialized = stringify(transaction["content"])
    except (ValueError, TypeError, UnicodeError):
        return False
    tx_hash = transaction.get("hash")
    spelled = tx_hash.lower() if "signed-hash-form" in off and isinstance(tx_hash, str) else tx_hash
    # A lenient implementation compares the hash in any hex case and verifies
    # the signature over the hash as given.
    if spelled != hashlib.sha256(serialized.encode("utf-8")).hexdigest():
        return False
    signature = transaction.get("signature")
    if "signed-signature-form" in off and isinstance(signature, dict) and isinstance(signature.get("data"), str):
        # A lenient implementation: any hex case, optional 0x, other members ignored.
        signature = {"type": signature.get("type"), "data": "0x" + signature["data"].removeprefix("0x").lower()}
    sender = _address(transaction["content"].get("from"), frozenset())
    if not (
        isinstance(signature, dict)
        and set(signature) == {"type", "data"}
        and signature["type"] == "ed25519"
        and isinstance(signature["data"], str)
        and SIGNATURE.fullmatch(signature["data"])
        and sender is not None
    ):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(sender)).verify(
            bytes.fromhex(signature["data"][2:]), tx_hash.encode("utf-8")
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def _exact_json(left, right) -> bool:
    """Equal as `JSON.stringify` spells them, member order included."""
    try:
        return stringify(left) == stringify(right)
    except (ValueError, TypeError, UnicodeError):
        return False


def _jcs_equal(left, right) -> bool:
    """Equal as DACS JCS bytes: member order is not significant."""
    try:
        return canonicalize(left) == canonicalize(right)
    except (ValueError, TypeError, UnicodeError):
        return False


def embeds_retained(response, transaction) -> bool:
    """A demosdk 4.0.16 `confirm()` result (RPCResponseWithValidityData) from
    the pinned node that reports the transaction valid and embeds exactly the
    retained signed transaction. `confirmTx` answers result 200 even when it
    refuses, so `valid` decides; the node later executes the embedded copy."""
    if not (isinstance(response, dict) and response.get("result") == 200
            and isinstance(response.get("response"), dict) and isinstance(transaction, dict)):
        return False
    body = response["response"]
    data = body.get("data")
    if not (isinstance(data, dict) and data.get("valid") is True and isinstance(data.get("transaction"), dict)
            and all(isinstance(body.get(member), dict) for member in ("signature", "rpc_public_key"))):
        return False
    embedded = data["transaction"]
    members = ("content", "hash", "signature")
    return _exact_json({k: embedded[k] for k in members if k in embedded},
                       {k: transaction[k] for k in members if k in transaction})


def bound(projection, transfer, inclusion, off) -> bool:
    """DEM-2: every retained value plus the observed inclusion block."""
    if projection is None:
        return False
    for guard, field in (
        ("bind-hash", "txHash"),
        ("bind-nonce", "nonce"),
        ("bind-sender", "sender"),
        ("bind-recipient", "recipient"),
        ("bind-amount", "amountOs"),
    ):
        if guard in off or field not in projection:
            continue
        if projection[field] != _retained(transfer, field):
            return False
    if "bind-block" in off:
        return True
    block = inclusion.get("blockNumber") if isinstance(inclusion, dict) else None
    if block is None:
        return "bind-requires-inclusion" in off
    return projection["blockNumber"] == block


def pinned(read, off) -> bool:
    """DEMOS-MAPPING §A.2 node pin: the binding configuration's own build
    attestation names exactly the profile commit, built from an unmodified
    tree. A self-report, another commit or a dirty tree is not the pin."""
    build = read.get("nodeBuild")
    if not (isinstance(build, dict) and set(build) == set(PINNED_BUILD)):
        return False
    return all(
        build[member] == PINNED_BUILD[member] or guard in off
        for guard, member in (
            ("node-build-attested", "source"),
            ("node-build-commit", "commit"),
            ("node-build-clean-tree", "tree"),
        )
    )


def sends_payment(record, off) -> bool:
    """A confirmed record can show payment only when its transaction carries
    the four edits of its send (each `txhash` blanked): the pinned node
    applies a missing or empty edit list as a successful no-op. Necessary,
    never sufficient: the applied-payment authority still decides."""
    return "confirmed-requires-send-edits" in off or edits_match(record["content"], off)


def is_confirmed(status, off) -> bool:
    if "success-requires-exact-confirmed" in off:
        return isinstance(status, str) and status.lower() in {
            "confirmed", "included", "finalized", "success",
        }
    return status == "confirmed"


def observed_block(protocol_input: dict):
    inclusion = protocol_input.get("inclusionObservation")
    return inclusion.get("blockId") if isinstance(inclusion, dict) else None


# `applied`'s default block: the observed inclusion's. A sentinel, so that a
# JSON null block ID is compared as null, never replaced by the observation.
_OBSERVED_BLOCK = object()


def applied(read, projection, protocol_input, off, block_id=_OBSERVED_BLOCK) -> str:
    """DEMOS-MAPPING §A.2 applied-payment authority for the handler (DEM-3) and
    the consumer (DEM-7): it names the phase's network, the inclusion block ID
    (`block_id`, by default the observed one), the projected transaction and
    parties, and a debit and credit of the OS amount. Without the network or
    block ID to compare it binds nothing."""
    if "success-requires-applied-transfer" in off:
        return "pass"
    proof = read.get("appliedTransfer")
    if not (
        read.get("appliedTransferAuthenticated") is True
        and isinstance(proof, dict)
        and set(proof) == APPLIED_TRANSFER
        and all(isinstance(proof[k], str) and DECIMAL.fullmatch(proof[k])
                for k in ("payerDebitOs", "payeeCreditOs"))
    ):
        return "indeterminate"
    # Its debit and credit are evidence only as the change of the committed
    # balances it authenticates; figures without that change prove nothing.
    if ("applied-transfer-is-committed-change" not in off
            and committed_change(proof) != (proof["payerDebitOs"], proof["payeeCreditOs"])):
        return "indeterminate"
    expected = {k: projection[k] for k in ("txHash", "blockNumber", "sender", "recipient")}
    if "applied-transfer-binds-network" not in off:
        network = _network(protocol_input.get("railNetwork"))
        if network is None:
            return "indeterminate"
        expected.update(network)
    if "applied-transfer-binds-block-id" not in off:
        if block_id is _OBSERVED_BLOCK:
            block_id = observed_block(protocol_input)
        if not (isinstance(block_id, str) and HASH.fullmatch(block_id)):
            return "indeterminate"
        expected["blockId"] = block_id
    if (not _safe_integer(proof["blockNumber"])
            or any(proof[k] != value for k, value in expected.items())
            or any(proof[k] != projection["amountOs"] for k in ("payerDebitOs", "payeeCreditOs"))):
        return "fail"
    return "pass"


def handler_result(expected: str, protocol_input: dict, off) -> tuple[str, dict]:
    want = dict(HANDLER_WANT[expected])
    if expected == "pass" and "success-authorizes-no-delivery" in off:
        want["deliveryAuthorized"] = True
        want["settlementAccounting"] = True
    if expected == "fail":
        if "failure-proof-retained" in off:
            want["terminalFailureProofRetained"] = False
        if "no-replacement" in off:
            want["replacementPermitted"] = True
    if expected == "indeterminate":
        if (
            "unresolved-authorizes-nothing" in off
            and protocol_input["statusIndex"] == "included"
        ):
            want["deliveryAuthorized"] = True
            want["settlementAccounting"] = True
        if "no-rebroadcast" in off and protocol_input["recordRead"]["state"] == "not-found":
            want["broadcastPermitted"] = True
    return expected, want


def classify(protocol_input: dict, off) -> tuple[str, dict]:
    """DEM-2..DEM-6 handler classification of one re-read."""
    if "success-requires-record" in off and protocol_input["statusIndex"] == "included":
        return handler_result("pass", protocol_input, off)
    read = protocol_input["recordRead"]
    record = read.get("record") if read.get("state") == "found" else None
    projection = decode(record, off) if record is not None else None
    status = projection["status"] if projection else None
    if protocol_input["inclusionObservation"] is None and "bind-requires-inclusion" in off and projection:
        # The wrong implementation fills a missing observation from the record
        # and the applied-payment authority it was given.
        proof = read.get("appliedTransfer")
        protocol_input = dict(protocol_input, inclusionObservation={
            "blockNumber": projection["blockNumber"],
            "blockId": proof.get("blockId") if isinstance(proof, dict) else None,
        })
    is_bound = pinned(read, off) and bound(
        projection,
        protocol_input["retainedTransfer"],
        protocol_input["inclusionObservation"],
        off,
    )
    if (is_bound and is_confirmed(status, off) and applied(read, projection, protocol_input, off) == "pass"
            and sends_payment(record, off) and observed_final(read, protocol_input, off)
            and "success-branch" not in off):
        return handler_result("pass", protocol_input, off)
    # DEM-4: only a bound failed record authenticated under FV-5 at its
    # bft-final inclusion is terminal. A plain RPC read of one is DEM-5: a
    # stale or dishonest pinned node can serve failed for an executed transfer.
    if status == "failed" and (is_bound or "failure-requires-binding" in off) and (
        proven_failure(read, protocol_input, off) or "failure-requires-authentication" in off
    ):
        if "failure-is-permanent" not in off:
            return handler_result("fail", protocol_input, off)
    return handler_result("indeterminate", protocol_input, off)


def valid_failure_proof(proof, transfer, off) -> bool:
    if not (isinstance(proof, dict) and proof.get("classification") == "permanent"):
        return False
    projection = decode(proof.get("record"), off)
    return (
        projection is not None
        and projection["status"] == "failed"
        and bound(projection, transfer, {"blockNumber": proof.get("inclusionBlock")}, off)
    )


FV5_RESULT = frozenset({"kind", "networkId", "genesisHash", "blockId", "transactionRef", "record", "attestations"})
# The settlement-finality verifier's optional signed member of that result.
FV5_APPLIED_TRANSFER = frozenset({
    "txHash", "blockNumber", "sender", "recipient", "payerDebitOs", "payeeCreditOs", "committedBalances",
})
# The proof's own block: a resume or an APR check has no inclusion
# observation of its own, and the signed result names the block.
_PROOF_BLOCK = object()


def fv5_applied_transfer(applied, record, off) -> bool:
    """A signed result MAY carry the settlement-finality corpus's
    `appliedTransfer`. Carried, it is part of what the authorities sign, so it
    must be the change of the committed balances it names, name the record's
    own transaction, block and parties, and move the record's OS amount when
    the record is `confirmed` and nothing when it is `failed`. A result that
    contradicts its own record authenticates nothing. This is the
    settlement-finality reference's own check, so both corpora apply one rule."""
    if "fv5-result-applied-transfer-binds-record" in off:
        return True
    return demos_applied_transfer_binds_record(applied, record)


def fv5_signed(result, policy) -> bool:
    """The result's attestations meet the trusted FV-5 policy: at least its
    threshold of distinct authority keys sign it over the FV domain. The
    settlement-finality reference's own FV-5 verifier checks them."""
    observation = {"networkId": result.get("networkId"), "genesisHash": result.get("genesisHash"),
                   "inclusionBlock": {"id": result.get("blockId")}, "executionResult": result}
    try:
        decision = _verify_demos_execution(observation, result.get("transactionRef"),
                                           {"demosExecutionPolicy": policy})[0]
    except (ValueError, TypeError, UnicodeError):
        return False
    return decision == "pass"


def fv5_result(result, record, protocol_input: dict, block, off) -> bool:
    """DACS-4 §9.7.0 FV-5 for a pay-dem record. `result` is the independent
    execution result that the trusted `fv5Policy` signs. It names the rail's
    network and genesis and the observed inclusion block ID, its transaction
    reference is the record's own hash and block, and it carries exactly
    `record`, with the FV verifier's optional `appliedTransfer`. A missing
    policy, a result signed by other keys or by too few, and a result for
    another network, block or record authenticate nothing."""
    if not (isinstance(result, dict) and FV5_RESULT <= set(result) <= FV5_RESULT | {"appliedTransfer"}
            and isinstance(record, dict)):
        return False
    if "appliedTransfer" in result and not fv5_applied_transfer(result["appliedTransfer"], record, off):
        return False
    if "fv5-result-signed" not in off and not fv5_signed(result, protocol_input.get("fv5Policy")):
        return False
    if "fv5-result-binds-rail-network" not in off:
        network = _network(protocol_input.get("railNetwork"))
        if network is None or {k: result[k] for k in NETWORK} != network:
            return False
    if block is not _PROOF_BLOCK and "fv5-result-binds-block-id" not in off and not (
        isinstance(block, str) and HASH.fullmatch(block) and result["blockId"] == block
    ):
        return False
    if "fv5-result-binds-record" not in off and not (
        # Signed over JCS bytes, the result's record is the read record up to
        # member order, which the signature does not cover.
        _jcs_equal(result["record"], record)
        # A ChainTxRef compares by its JCS bytes, as the settlement-finality
        # reference compares it.
        and _jcs_equal(result["transactionRef"],
                       {"kind": "demos", "txHash": record.get("hash"), "blockNumber": record.get("blockNumber")})
    ):
        return False
    return True


def fv5_authenticated(read, protocol_input: dict, off, reference=None) -> bool:
    """A found read whose record FV-5 authenticates at the observed
    inclusion. A read that only says so (`authenticated: true`) is a plain
    read, whoever says it. For a consumer, `reference` is the signed `txRef`:
    as in the settlement-finality reference, a result authenticates only the
    transaction it names, so a result about another transaction or block is
    no result for this evidence and refutes nothing."""
    if "fv5-authentication-is-a-signed-result" in off and read.get("authenticated") is True:
        # The wrong implementation takes a flag for FV-5.
        return True
    if read.get("state") != "found":
        return False
    if reference is not None and "fv5-result-binds-signed-reference" not in off:
        result = read.get("executionResult")
        if not (isinstance(result, dict) and _jcs_equal(result.get("transactionRef"), reference)):
            return False
    inclusion = protocol_input.get("inclusionObservation")
    block = inclusion.get("blockId") if isinstance(inclusion, dict) else None
    return fv5_result(read.get("executionResult"), read.get("record"), protocol_input, block, off)


def inclusion_verdict(observation, reference, protocol_input: dict, off) -> str:
    """FV's own four-valued verdict on one transaction's `bft-final`
    inclusion: the settlement-finality reference's
    `verify_transaction_inclusion` under the rail's signed profile and the
    verifier's own trust. Without an observation, or without a `bft-final`
    profile for the rail's network or trust to check it, nothing is shown
    (`indeterminate`). A forged certificate, a transaction proven absent or
    a block off the authenticated head is FV's `fail`."""
    if "bft-final-inclusion-verified" in off:
        # The wrong implementation takes the inclusion on trust.
        return "pass"
    if not (isinstance(observation, dict) and isinstance(reference, dict)):
        return "indeterminate"
    profile, trust = protocol_input.get("finalityProfile"), protocol_input.get("finalityTrust")
    network = _network(protocol_input.get("railNetwork"))
    if not (isinstance(profile, dict) and profile.get("kind") == "bft-final" and network is not None
            and {k: profile.get(k) for k in NETWORK} == network and isinstance(trust, dict)):
        return "indeterminate"
    try:
        return verify_transaction_inclusion(observation, profile, reference, trust)[0]
    except (ValueError, TypeError, UnicodeError):
        return "error"


def bft_final(observation, reference, block_id, protocol_input: dict, off) -> bool:
    """The FV `bft-final` verification of one transaction's inclusion (the
    settlement-finality reference's own `verify_transaction_inclusion`:
    network, transaction proof, inclusion block, authenticated head and
    ancestry, BFT certificate) under the rail's signed `bft-final` profile
    and the verifier's own trust, in the block `block_id`. Every final
    verdict about a Demos payment needs it: DEM-3 success (PC-7 rail
    finality), DEM-4 failure, DEM-7's refutation and delivery. A record or a
    signed result can be about a block that is not final; this is what
    shows that it is."""
    if not (isinstance(observation, dict) and isinstance(reference, dict)):
        return False
    if inclusion_verdict(observation, reference, protocol_input, off) != "pass":
        return False
    if "bft-final-inclusion-binds-result-block" not in off:
        block = observation.get("inclusionBlock")
        if not (isinstance(block, dict) and isinstance(block_id, str) and block.get("id") == block_id):
            return False
    return True


def bft_final_inclusion(observation, record, result, protocol_input: dict, off) -> bool:
    """DEM-4's other half: the `bft-final` inclusion of the failed record's
    own transaction in the block that the signed execution result names."""
    if "failure-requires-bft-final-inclusion" in off:
        # The wrong implementation takes the signed result alone as DEM-4.
        return True
    if not (isinstance(record, dict) and isinstance(result, dict)):
        return False
    reference = {"kind": "demos", "txHash": record.get("hash"), "blockNumber": record.get("blockNumber")}
    return bft_final(observation, reference, result.get("blockId"), protocol_input, off)


def observed_final(read, protocol_input: dict, off) -> bool:
    """DEM-3 and PC-7: the payer returns `ok: true` only once the retained
    transaction's inclusion in the observed block is `bft-final`. A bound
    confirmed record from a block that no certificate finalizes, that is off
    the authenticated head or that is another block is no payment yet."""
    if "success-requires-bft-final-inclusion" in off:
        # The wrong implementation takes a bound confirmed record as final.
        return True
    transfer, inclusion = protocol_input.get("retainedTransfer"), protocol_input.get("inclusionObservation")
    if not (isinstance(transfer, dict) and isinstance(inclusion, dict)):
        return False
    reference = {"kind": "demos", "txHash": transfer.get("txHash"), "blockNumber": inclusion.get("blockNumber")}
    return bft_final(read.get("inclusionProof"), reference, inclusion.get("blockId"), protocol_input, off)


def presented_final(read, protocol_input: dict, guard: str, off) -> bool:
    """A consumer's `bft-final` check of the presented reference's inclusion
    in the block that FV-5's signed result names (the observed block, which
    that result must name; the observed block when there is none), as the
    settlement-finality reference checks the path before any execution
    result decides: DEM-7's `fail` and delivery's `pass` each need it."""
    if guard in off:
        # The wrong implementation lets the signed result decide alone.
        return True
    evidence = protocol_input.get("signedEvidence")
    reference = evidence.get("txRef") if isinstance(evidence, dict) else None
    result, inclusion = read.get("executionResult"), protocol_input.get("inclusionObservation")
    named = result if isinstance(result, dict) else inclusion if isinstance(inclusion, dict) else {}
    return bft_final(read.get("inclusionProof"), reference, named.get("blockId"), protocol_input, off)


def proven_failure(read, protocol_input: dict, off) -> bool:
    """DEM-4 for a read: FV-5 authenticates its record at the observed
    inclusion, and FV's bft-final verification shows that inclusion."""
    if "fv5-authentication-is-a-signed-result" in off and read.get("authenticated") is True:
        # The wrong implementation takes the earlier draft's flag for both.
        return True
    return fv5_authenticated(read, protocol_input, off) and bft_final_inclusion(
        read.get("inclusionProof"), read.get("record"), read.get("executionResult"), protocol_input, off)


def authenticated_proof(proof, protocol_input: dict, off) -> bool:
    """The proof carries FV-5's signed execution result for its own failed
    record, on the rail's network, and FV's bft-final inclusion of its
    transaction in the block that result names. A label (`fv5-bft-final`),
    a plain read (`rpc-read`), another result or a result without its
    finalized inclusion is no authentication: the verifier checks both
    itself and never trusts the handler that stored them."""
    if not isinstance(proof, dict):
        return False
    if "fv5-authentication-is-a-signed-result" in off and proof.get("authentication") == "fv5-bft-final":
        # The wrong implementation takes the handler's label for FV-5.
        return True
    return fv5_result(proof.get("authentication"), proof.get("record"), protocol_input, _PROOF_BLOCK, off) and (
        bft_final_inclusion(proof.get("inclusionProof"), proof.get("record"), proof.get("authentication"),
                            protocol_input, off))


def resume(protocol_input: dict, off) -> tuple[str, dict]:
    proof = protocol_input["retainedFailureProof"]
    if proof is not None and "resume-reuses-failure-proof" not in off:
        if "resume-validates-failure-proof" in off or (
            valid_failure_proof(proof, protocol_input["retainedTransfer"], off)
            # A plain-read proof (an earlier draft's DEM-4) is never reused:
            # the resume re-reads the retained hash instead.
            and (authenticated_proof(proof, protocol_input, off) or "resume-requires-authenticated-proof" in off)
        ):
            return handler_result("fail", protocol_input, off)
    expected, want = classify(protocol_input, off)
    if proof is not None and expected == "pass" and "terminal-never-reopens" not in off:
        # DEM-6: the phase ended on its retained failure. The re-read that
        # replaces a proof that no longer verifies is post-terminal: it can
        # prove the failure again, but it never reopens the phase as paid.
        return handler_result("indeterminate", protocol_input, off)
    return expected, want


def apr_evidence(protocol_input: dict, off) -> tuple[str, dict]:
    """A DEM-4 failure proof offered as APR `closed-cannot-settle`
    reconciliation evidence: only a bound failed record authenticated under
    FV-5 at its `bft-final` inclusion qualifies, never a plain RPC read."""
    refused = ("indeterminate", {"reconciliationEvidence": False})
    proof = protocol_input["retainedFailureProof"]
    if not valid_failure_proof(proof, protocol_input["retainedTransfer"], off):
        return refused
    authenticated = authenticated_proof(proof, protocol_input, off)
    if authenticated or "apr-evidence-requires-authenticated-failure" in off:
        if "apr-evidence-from-authenticated-failure" not in off:
            return "pass", {"reconciliationEvidence": True}
    return refused


def complete_transfer(transfer) -> bool:
    return (
        isinstance(transfer, dict)
        and set(transfer) == RETAINED
        and isinstance(transfer["jobId"], str)
        and transfer["jobId"] != ""
        and _safe_integer(transfer["phaseIndex"])
        and isinstance(transfer["phaseIndex"], int)
        and _safe_integer(transfer["nonce"])
        and isinstance(transfer["nonce"], int)
        and all(
            isinstance(transfer[field], str) and HASH.fullmatch(transfer[field])
            for field in ("txHash", "sender", "recipient")
        )
        and isinstance(transfer["amountOs"], str)
        and DECIMAL.fullmatch(transfer["amountOs"]) is not None
    )


def party_address(value, off):
    """The 64-hex Demos key a phase's `payer.payingKey` or
    `payee.payeeAddress` projects to, or None when it is in no pay-dem form."""
    if "phase-party-address-projects" in off:
        # The wrong implementation compares the phase's spelling as given.
        return value
    match = (PARTY_ADDRESS.fullmatch(value) or PARTY_CLAIM_PARAMETERS.fullmatch(value)) if isinstance(value, str) else None
    return match[1] if match else None


# DACS-1 §6.3.2 step (6) mechanisms as a verifier's own check of the pinned
# bundle reports them (the corpus models that result), or "none".
CLAIM_CONTROLS = frozenset({"presentation-signature", "sr1-linkage", "holder-binding", "demos-gcr-domain"})
# The one mechanism DACS-1 defines for a Demos key claim's scheme: the exact
# `key:` claim's own bundle presentation signature. `did:demos:agent:` has none.
KEY_CLAIM_CONTROL = {"key": "presentation-signature"}


def payer_claims(phase, off):
    """The 64-hex keys of the controlled Demos key claims of the payer's party
    bundle (DEMOS-MAPPING §A.2) that DEM-1 and DEM-7 bind a sender to, or None
    when the phase's claims are malformed. A bundle that lists a key with no
    proof of control, a claim of a scheme that is no Demos key, or a control
    that DACS-1 does not define for the claim's scheme adds nothing. Without
    `payerKeyClaims` this corpus's bundle holds one `key:` claim for the
    handler's `payer.payingKey`, controlled by its presentation signature."""
    claims = phase.get("payerKeyClaims")
    if claims is None:
        key = party_address(phase.get("payerPayingKey"), off)
        return None if key is None else {key}
    if not (isinstance(claims, list) and claims and all(
            isinstance(claim, dict) and set(claim) == {"claim", "control"} and isinstance(claim["claim"], str)
            and isinstance(claim["control"], str) and (claim["control"] in CLAIM_CONTROLS or claim["control"] == "none")
            for claim in claims)):
        return None
    listed = "consumer-binds-controlled-claims-only" in off
    keys = set()
    for claim in claims:
        if "claims-are-claim-references" in off:
            # The wrong implementation projects a claim as it projects an
            # address: bare and 0x hex and a cci-xm: address become claims.
            match = re.fullmatch(r"(?:0x|did:demos:agent:|key:|cci-xm:demos:[a-z]+:0x)?([0-9a-f]{64})", claim["claim"])
            if match and (listed or claim["control"] in CLAIM_CONTROLS):
                keys.add(match[1])
            continue
        match = DEMOS_KEY_CLAIM.fullmatch(claim["claim"])
        # The wrong implementation matches the whole reference string, so a
        # `?<parameters>` suffix DACS-1 has a reader ignore makes the claim none.
        if not match or ("claim-reference-parameters-ignored" in off and "?" in claim["claim"]):
            continue
        # The wrong implementation takes any step (6) mechanism as control of any scheme.
        controlled = (claim["control"] in CLAIM_CONTROLS if "control-is-the-schemes-mechanism" in off
                      else KEY_CLAIM_CONTROL.get(match[1]) == claim["control"])
        if listed or controlled:
            keys.add(match[2])
    return keys


def paying_key_controlled(phase, off):
    """DEM-1: the sender, the key of `payer.payingKey`, is the key of a
    controlled Demos key claim of the retained payer bundle."""
    payers, key = payer_claims(phase, off), party_address(phase.get("payerPayingKey"), off)
    return payers is not None and key in payers


# Every input a final pay-dem verdict consumes, as one network's binding
# members: DEM-2's pinned nodes, DEM-3's applied-payment authority, the
# profile's fork scope, the bft-final trust DEM-3, DEM-4 and DEM-7 verify
# inclusion under, and the FV-5 policy DEM-4 authenticates a failure under.
BINDING = ("pinnedNodes", "appliedPaymentAuthority", "gasFeeSeparation", "bftFinalTrust", "executionResultPolicy")
BFT_FINAL_TRUST = frozenset({"validatorSets", "observationAuthorityKeys"})
EXECUTION_POLICY = frozenset({"kind", "threshold", "authorityKeys"})
# Each binding that is not the rail network's, and the guard that refuses it.
NETWORK_VARIANTS = {
    "binding-for-another-network": "binding-network-is-rail-network",
    "binding-for-replaced-genesis": "binding-network-is-rail-network",
    "pinned-nodes-for-another-network": "pinned-nodes-bind-rail-network",
    "applied-authority-for-another-network": "applied-authority-binds-rail-network",
    "fork-attestation-of-another-genesis": "fork-attestation-binds-rail-genesis",
    "bft-final-trust-for-another-network": "bft-final-trust-binds-rail-network",
    "execution-policy-for-another-network": "execution-policy-binds-rail-network",
}
# bft-final trust for the rail's network that is present but that the FV
# verifier's own check rejects, so it can never verify an inclusion.
UNUSABLE_TRUST = ("bft-final-trust-validator-set-not-pinned", "bft-final-trust-undecodable-observation-keys",
                  "bft-final-trust-aliased-observation-keys")
UNSELECTABLE = frozenset({"disabled", "failed", "mocked"})
RAV_R3_GATED = frozenset({"operator_gated", "closed_data", "bilateral"})


def _network(value):
    """A (networkId, genesisHash) pair of non-empty strings, or None."""
    if (isinstance(value, dict) and set(value) == NETWORK
            and all(isinstance(value[k], str) and value[k] for k in NETWORK)):
        return dict(value)
    return None


def covers_profile(trust: dict, protocol_input: dict, off) -> bool:
    """The bft-final trust can verify the rail's inclusion: the rail's signed
    `bft-final` profile (`finalityProfile`) names `railNetwork`, and the FV
    verifier's own trust check passes it for that profile: the validator set
    the profile pins, hashing to its content hash with well-formed members,
    and at least the profile's threshold of its observation authorities with
    distinct keys that decode."""
    profile, rail = protocol_input.get("finalityProfile"), _network(protocol_input.get("railNetwork"))
    if not (isinstance(profile, dict) and profile.get("kind") == "bft-final" and rail is not None
            and {k: profile.get(k) for k in NETWORK} == rail):
        return False
    trusted = {key: trust[key] for key in BFT_FINAL_TRUST}
    if "bft-final-trust-verifies-profile" in off:
        # The wrong implementation counts trust that is present as trust that
        # verifies: some set under the pinned hash, some string per authority.
        sets, keys = trusted["validatorSets"], trusted["observationAuthorityKeys"]
        observation = profile.get("observation") or {}
        held = [name for name in observation.get("authorityRefs") or [] if isinstance(keys, dict)
                and isinstance(keys.get(name), str)]
        return (isinstance(sets, dict) and isinstance(sets.get((profile.get("validatorSetRef") or {}).get("contentHash")), dict)
                and len(held) >= (observation.get("threshold") or 1))
    return bft_final_trust(profile, trusted)[0] == "pass"


def binding_members(protocol_input: dict, off) -> dict[str, bool]:
    """DEM-1/RAV-R3: which `BINDING` members the payer's Demos binding holds
    for the rail's network. That network is the pinned RailDefinition's
    `consumerFinalityProfile.settlement` (`railNetwork`), never one the
    binding supplies; the binding entry is the one for that network, and a
    member counts only when it names exactly that network and genesis. The
    bft-final trust must also cover the rail's signed profile, and the FV-5
    policy must be one the FV verifier applies: a member that can never
    verify is no member."""
    held = dict.fromkeys(BINDING, False)
    entries = protocol_input.get("demosBinding")
    if not (isinstance(entries, list) and all(isinstance(entry, dict) for entry in entries)):
        return held
    if "binding-network-is-rail-network" in off:
        # The wrong implementation keeps one binding and takes the phase's
        # network from it, whatever the rail settles on.
        entry = entries[0] if entries else None
        network = _network({k: entry.get(k) for k in NETWORK}) if entry is not None else None
    else:
        network = _network(protocol_input.get("railNetwork"))
        entry = next((entry for entry in entries
                      if network is not None and {k: entry.get(k) for k in NETWORK} == network), None)
    if entry is None or network is None:
        return held
    for member, guard, extra in (
        ("pinnedNodes", "pinned-nodes-bind-rail-network", set()),
        ("appliedPaymentAuthority", "applied-authority-binds-rail-network", set()),
        # The sealed genesis's forks.gasFeeSeparation: only a null height is unscheduled.
        ("gasFeeSeparation", "fork-attestation-binds-rail-genesis", {"activationHeight"}),
        ("bftFinalTrust", "bft-final-trust-binds-rail-network", BFT_FINAL_TRUST),
        ("executionResultPolicy", "execution-policy-binds-rail-network", EXECUTION_POLICY),
    ):
        value = entry.get(member)
        if not (isinstance(value, dict) and set(value) == NETWORK | extra):
            continue
        if guard not in off and {k: value[k] for k in NETWORK} != network:
            continue
        if member == "gasFeeSeparation" and value["activationHeight"] is not None:
            continue
        if member == "bftFinalTrust" and not covers_profile(value, protocol_input, off):
            continue
        if (member == "executionResultPolicy"
                and demos_execution_policy({k: value[k] for k in EXECUTION_POLICY})[0] != "pass"):
            continue
        held[member] = True
    return held


def rail_preflight(protocol_input: dict, off) -> tuple[str, dict]:
    """RAV-R3 for a new production session, before rail selection and so
    before Agreement signature and the PIPE-6 commitment: a `pay-dem` rail is
    selectable only when the payer's Demos binding holds every DEM-1 member
    for the rail's network, whatever availability the rail shows."""
    availability = protocol_input["availability"]
    if availability not in UNSELECTABLE | RAV_R3_GATED | {"live"}:
        return "error", {"railSelectable": False}
    if availability in UNSELECTABLE:
        return "fail", {"railSelectable": False}
    gated = availability in RAV_R3_GATED or "pay-dem-preflight-whatever-availability" not in off
    if gated and "preflight-requires-binding" not in off and not all(binding_members(protocol_input, off).values()):
        return "fail", {"railSelectable": False}
    # The payer's bundle, when the preflight holds it, must control a Demos key
    # claim: DEM-1 signs for no other key, so a bundle that controls none (a
    # session-key presentation, a listing only) is refused here, before the
    # Agreement is signed, not at settle.
    if gated and "payerKeyClaims" in protocol_input and "preflight-requires-controlled-key-claim" not in off:
        if not payer_claims({"payerKeyClaims": protocol_input["payerKeyClaims"]}, off):
            return "fail", {"railSelectable": False}
    if "preflight-selects-configured-rail" in off:
        return "fail", {"railSelectable": False}
    return "pass", {"railSelectable": True}


def pre_sign_gate(protocol_input: dict, off) -> tuple[str, dict]:
    """DEM-1 before signing: a Demos binding without pinned nodes, an
    applied-payment authority, a genesis attestation that `gasFeeSeparation`
    is unscheduled, bft-final trust covering the rail's profile or an FV-5
    execution-result policy cannot reach DEM-3 success or a DEM-4 proof, so a
    transfer sent under it could only end unresolved. The RAV-R3 preflight
    checked the binding before the rail was selected, so at settle the rail
    is non-operational for this payer: RAV-R4 substrate, and nothing is signed.
    A phase whose paying key or payee address does not project as a pay-dem
    party address can never be paid: PC-4 `permanent` before anything is
    signed or retained, so no retention pins the phase."""
    phase = protocol_input.get("phase") or {}
    if "pre-sign-party-address-projects" not in off and any(
            party_address(phase.get(field), off) is None for field in ("payerPayingKey", "payeeAddress")):
        return "error", {"signPermitted": False, "ok": False, "errorClass": "permanent"}
    # A paying key DEM-7 will not bind could pay, never be admitted, and
    # allow no replacement: refused as a phase that can never be paid.
    if "pre-sign-paying-key-controlled" not in off and not paying_key_controlled(phase, off):
        return "error", {"signPermitted": False, "ok": False, "errorClass": "permanent"}
    held = binding_members(protocol_input, off)
    for guard, member in (
        ("sign-requires-pinned-node", "pinnedNodes"),
        ("sign-requires-applied-payment-authority", "appliedPaymentAuthority"),
        ("sign-requires-gas-fee-separation-unscheduled", "gasFeeSeparation"),
        ("sign-requires-bft-final-trust", "bftFinalTrust"),
        ("sign-requires-execution-result-policy", "executionResultPolicy"),
    ):
        if not held[member] and guard not in off:
            # The wrong implementation blames the payer for a rail that is not
            # operational (RAV-R4), after the payee may already have delivered.
            error_class = "permanent" if "binding-refusal-is-rail-unavailable" in off else "substrate"
            return "fail", {"signPermitted": False, "ok": False, "errorClass": error_class}
    if "sign-allowed-when-configured" in off:
        return "fail", {"signPermitted": False, "ok": False, "errorClass": "substrate"}
    return "pass", {"signPermitted": True, "ok": None, "errorClass": None}


def broadcast_gate(protocol_input: dict, off) -> tuple[str, dict]:
    """DEM-1 at the first egress of the signed transaction (a `confirm`
    request or the broadcast) for the authenticated phase, then DEM-6."""
    refused = ("fail", {"broadcastPermitted": False})
    request = protocol_input["request"]
    if request not in REQUESTS:
        if "egress-only-confirm-then-broadcast" not in off:
            return refused
        # The wrong implementation sends the signed bytes by another route
        # (an SR-3 proxy, a direct wallet submission) after the confirm checks.
        request = "confirm-retained"
    if request == "confirm-retained" and "retention-before-first-egress" in off:
        # The wrong implementation checks DEM-1 only at `broadcast` and sends
        # the signed bytes to `confirmTx` unchecked.
        return "pass", {"broadcastPermitted": True}
    transfer = protocol_input["retainedTransfer"]
    phase = protocol_input["phase"]
    if not complete_transfer(transfer) and "broadcast-requires-complete-retention" not in off:
        return "error", {"broadcastPermitted": False}
    state = protocol_input["broadcastState"]
    if protocol_input.get("restartedSinceRetention") is not False and "restart-is-maybe-broadcast" not in off:
        # DEM-6: a transfer retained before a (re)start may have left in a
        # call the crash kept from being journaled, whatever state was recorded.
        state = "maybe-broadcast"
    if state == "confirm-sent-interrupted" and "confirm-egress-may-broadcast" in off:
        # The wrong implementation counts only a recorded broadcast.
        state = "never-broadcast"
    if (state == "confirm-returned" and request == "broadcast-retained"
            and "submission-completes-own-confirm" not in off):
        # The one broadcast that completes the uninterrupted submission.
        state = "never-broadcast"
    if state != "never-broadcast":
        if request == "broadcast-replacement":
            if "no-replacement" not in off:
                return refused
        elif "no-rebroadcast" not in off:
            return refused
    if request != "confirm-retained":
        # demosdk broadcast(validationData) carries the confirm result, not the
        # retained transaction, and the pinned node executes the copy embedded
        # in it. Only this submission's own response may complete it.
        own = protocol_input.get("confirmResponse")
        carried = protocol_input.get("validityResponse")
        if "broadcast-carries-own-validity-response" not in off and (
            own is None or carried is None or not _exact_json(carried, own)
        ):
            return refused
        if "validity-response-binds-retained-transfer" not in off and not embeds_retained(
            own, protocol_input["signedTransaction"]
        ):
            return refused
    held = binding_members(protocol_input, off)
    for guard, member in (
        ("broadcast-requires-pinned-node", "pinnedNodes"),
        ("broadcast-requires-applied-payment-authority", "appliedPaymentAuthority"),
        ("broadcast-requires-gas-fee-separation-unscheduled", "gasFeeSeparation"),
        ("broadcast-requires-bft-final-trust", "bftFinalTrust"),
        ("broadcast-requires-execution-result-policy", "executionResultPolicy"),
    ):
        if not held[member] and guard not in off:
            return refused
    if "retention-bound-to-phase" not in off and (
        transfer.get("jobId"), transfer.get("phaseIndex")
    ) != (phase["jobId"], phase["phaseIndex"]):
        return refused
    amount = phase.get("amount", {})
    spelling = amount.get("amount")
    match = re.fullmatch(r"(0|[1-9][0-9]*)(?:\.([0-9]{1,9}))?", spelling) if isinstance(spelling, str) else None
    if amount.get("currency") != "DEM" or match is None:
        return "error", {"broadcastPermitted": False}
    # 10^9 OS per DEM, by spelling: no int() on the untrusted decimal.
    phase_os = (match[1] + (match[2] or "").ljust(9, "0")).lstrip("0") or "0"
    parties = {field: party_address(phase.get(field), off) for field in ("payerPayingKey", "payeeAddress")}
    if None in parties.values():
        return "error", {"broadcastPermitted": False}
    if "broadcast-paying-key-controlled" not in off and not paying_key_controlled(phase, off):
        return "error", {"broadcastPermitted": False}
    for guard, field, authority in (
        ("retained-sender-is-payer", "sender", "payerPayingKey"),
        ("retained-recipient-is-payee", "recipient", "payeeAddress"),
        ("retained-amount-is-phase-amount", "amountOs", "amountOs"),
    ):
        if guard not in off and transfer.get(field) != (phase_os if field == "amountOs" else parties[authority]):
            return refused
    if "signed-transaction-authentic" not in off and not authentic(
        protocol_input["signedTransaction"], off
    ):
        return refused
    if "signed-transfer-matches-retention" not in off:
        projection = decode(protocol_input["signedTransaction"], off, executed=False)
        if projection is None or any(
            projection[field] != (
                _lenient_spelling(transfer.get(field)) if field == "amountOs" else _retained(transfer, field)
            )
            for field in ("txHash", "nonce", "sender", "recipient", "amountOs")
        ):
            return refused
    if protocol_input["hashRetainedForOtherPhases"] and "no-cross-phase-reuse" not in off:
        return refused
    if not protocol_input["retentionDurable"] and (
        "broadcast-requires-durable-retention" not in off
    ):
        return refused
    if "first-broadcast-allowed" in off:
        return refused
    return "pass", {"broadcastPermitted": True}


# Outcomes that refuse the transfer: demosdk confirm() or broadcast() with
# valid false (for example "Insufficient balance"), the handler's own balance
# read before any egress, and its DEM-1 refusal of the completing broadcast.
CALL_REFUSALS = frozenset({"insufficient-balance", "refused-not-valid", "refused-by-dem1"})


def egress_outcome(protocol_input: dict, off) -> tuple[str, dict]:
    """The PC-4 class once the handler's own pre-egress check, `confirm` or
    `broadcast` returns. From the first egress on a node may hold the signed
    bytes, so every outcome is DEM-5 substrate with the retained hash kept and
    no further call; only a refusal found before it is permanent."""
    call, outcome = protocol_input["call"], protocol_input["outcome"]
    cause = f"{call}:{outcome}"
    unresolved = ("indeterminate", dict(HANDLER_WANT["indeterminate"], cause=cause))
    state = protocol_input["broadcastState"]
    if protocol_input.get("restartedSinceRetention") is not False and "restart-is-maybe-broadcast" not in off:
        state = "maybe-broadcast"
    if state == "confirm-sent-interrupted" and "confirm-egress-may-broadcast" in off:
        state = "never-broadcast"
    # Any call, including an unrecognized one, may have carried the bytes.
    sent = call != "pre-egress-check" or state != "never-broadcast"
    if outcome == "accepted" and call == "broadcast" and "success-requires-record" in off:
        # The wrong implementation reports an accepted broadcast as paid.
        return "pass", dict(HANDLER_WANT["pass"], cause=cause)
    if outcome in CALL_REFUSALS:
        if not sent and outcome == "insufficient-balance":
            if "pre-egress-refusal-is-permanent" in off:
                return unresolved
            return "fail", dict(NOT_SENT_WANT, cause=cause)
        if sent and "post-egress-refusal-is-unresolved" in off:
            # The wrong implementation follows the bare PC-4 row "refused by
            # chain, insufficient balance" after the bytes have left.
            return "fail", dict(NOT_SENT_WANT, cause=cause)
        return unresolved
    if outcome != "accepted" and "call-error-is-unresolved" in off:
        # The wrong implementation classifies an RPC failure, a timeout or an
        # unrecognized reply as PC-4 transient and repeats the call.
        return "indeterminate", dict(unresolved[1], errorClass="transient", nextAction="repeat-call",
                                     onPauseExpiry=None, broadcastPermitted=True)
    return unresolved


def authority_refutes(read, projection, protocol_input: dict, reference, off) -> bool:
    """DEM-7 and the Finality rule: an applied-payment authority's
    contradiction is `fail` only about the presented reference's final
    inclusion, which FV's bft-final verification shows in the block the
    authority names, and only when it still contradicts against that verified
    block. The observed block ID is a plain read: a stale or forked node that
    names another block contradicts nothing, and an authority about a block
    no certificate finalizes, a fork or another block refutes nothing."""
    if "consumer-contradiction-requires-bft-final-inclusion" in off:
        # The wrong implementation refutes on the plain observation alone.
        return True
    block = read["appliedTransfer"].get("blockId")
    return bft_final(read.get("inclusionProof"), reference, block, protocol_input, off) and (
        applied(read, projection, protocol_input, off, block) == "fail")


def dem7(protocol_input: dict, off) -> str:
    """DEM-7 consumer gate, including the payee before delivery."""
    if (
        "consumer-requires-confirmed-record" in off
        and protocol_input["statusIndex"] == "included"
    ):
        return "pass"
    phase = protocol_input["phase"]
    payers, payee = payer_claims(phase, off), party_address(phase.get("payeeAddress"), off)
    read = protocol_input["recordRead"]
    if "consumer-claims-before-fv-inclusion-verdict" in off:
        # The wrong implementation decides the phase's own claims first, so a
        # bundle that controls nothing turns FV-10's fail into indeterminate.
        if payers is None or payee is None:
            return "error"
        if not payers:
            return "indeterminate"
    # FV-10: FV's own error or fail on the presented reference's bft-final
    # inclusion (a forged certificate, a transaction proven absent, a block
    # off the authenticated head) is the evidence's verdict before any
    # uncertainty, the verdict the settlement-finality corpus gives the same
    # input. FV's indeterminate refutes nothing and decides nothing here.
    if "consumer-takes-fv-inclusion-verdict" not in off and "inclusionProof" in read:
        verdict = inclusion_verdict(read["inclusionProof"], protocol_input["signedEvidence"]["txRef"],
                                    protocol_input, off)
        if verdict in ("fail", "error"):
            return verdict
    # After FV-10: a malformed phase value or claim is error, and a bundle
    # that controls no Demos key claim authenticates no sender.
    if payers is None or payee is None:
        return "error"
    if not payers:
        return "indeterminate"
    record = read.get("record") if read.get("state") == "found" else None
    projection = decode(record, off) if record is not None else None
    reference = protocol_input["signedEvidence"]["txRef"]
    # DEM-7 binds a record two ways: from a pinned node (a plain read) or as
    # FV-5 authenticates it. A signed result carries its own record, so the
    # build of the node that served the plain read is not what it rests on.
    signed = fv5_authenticated(read, protocol_input, off, reference)
    if projection is None or not (signed and "consumer-fv5-record-binds-without-node-pin" not in off or pinned(read, off)):
        return "indeterminate"
    expected_values = {
        "txHash": reference["txHash"],
        "blockNumber": reference["blockNumber"],
        "sender": payers,
        "recipient": payee,
        "amountOs": _canonical(phase["amountOs"]),
    }
    is_bound = all(
        (projection[field] in value if field == "sender" else projection[field] == value)
        or f"consumer-binds-{guard}" in off
        for (field, value), guard in zip(expected_values.items(), ("hash", "block", "payer", "payee", "amount"))
    )
    status = projection["status"]
    if is_bound and is_confirmed(status, off):
        decision = applied(read, projection, protocol_input, off)
        if decision == "fail" and not authority_refutes(read, projection, protocol_input, reference, off):
            decision = "indeterminate"
        if decision != "pass":
            return "indeterminate" if "consumer-authenticated-contradiction-fails" in off else decision
        # A signed result is hashed over JCS bytes, which do not keep member
        # order: for a record FV-5 authenticates the edits compare by member,
        # as the settlement-finality reference compares them. A plain read is
        # the node's own text, whose member order the node compares.
        if not (sends_payment(record, off) if not signed or "consumer-fv5-edit-members-compare-by-name" in off
                else "confirmed-requires-send-edits" in off or _demos_send_edits_match(record["content"])):
            return "indeterminate"
        return "indeterminate" if "consumer-admits-confirmed" in off else "pass"
    # FV-5's signed result refutes the payment only with the bft-final
    # inclusion of the presented reference in the block it names: a signed
    # failure about a fork or an unfinalized block decides nothing.
    authenticated = signed and presented_final(
        read, protocol_input, "consumer-refutation-requires-bft-final-inclusion", off)
    if is_bound and status == "failed" and (
        authenticated or "consumer-failed-requires-authentication" in off
    ):
        return "indeterminate" if "consumer-failed-refutes" in off else "fail"
    if (
        not is_bound
        and authenticated
        and "consumer-authenticated-contradiction-fails" not in off
    ):
        return "fail"
    return "indeterminate"


def admit(protocol_input: dict, off) -> tuple[str, dict]:
    verdict = dem7(protocol_input, off)
    return verdict, {"dem7GatePassed": verdict == "pass", "deliveryAuthorized": False}


ADMISSION = frozenset({"txRef", "jobId", "phaseIndex"})


def valid_admission(admission) -> bool:
    """One admitted reference: its raw `txRef`, the `(jobId, phaseIndex)` it
    was admitted for. No Demos reference is legacy evidence (SB-1), so the
    admission has no `legacy` member.
    The reference payee validates its index with this same check."""
    return (
        isinstance(admission, dict)
        and set(admission) == ADMISSION
        and isinstance(admission["txRef"], dict)
        and isinstance(admission["jobId"], str) and admission["jobId"] != ""
        and isinstance(admission["phaseIndex"], int) and _safe_integer(admission["phaseIndex"])
    )


def admission_index(index, off=frozenset()) -> bool:
    """A snapshot of the payee's durable admission index: its revision and
    every admission it holds, each well formed. A malformed admission is no
    history: it is never skipped or read as another phase's."""
    return (
        isinstance(index, dict)
        and set(index) == {"revision", "admissions"}
        and isinstance(index["revision"], int)
        and _safe_integer(index["revision"])
        and isinstance(index["admissions"], list)
        and all(isinstance(admission, dict) for admission in index["admissions"])
        and ("delivery-admission-entries-validated" in off
             or all(valid_admission(admission) for admission in index["admissions"]))
    )


def history(admissions) -> list:
    """Admissions compared as a multiset of their exact JCS bytes."""
    return sorted(canonicalize(admission) for admission in admissions)


def admit_for_delivery(protocol_input: dict, off) -> tuple[str, dict]:
    gate = dem7(protocol_input, off)

    def result(expected: str) -> tuple[str, dict]:
        return expected, {
            "dem7GatePassed": gate == "pass",
            "deliveryAuthorized": expected == "pass",
            "settlementAccounting": expected == "pass",
        }

    if gate != "pass" and "delivery-requires-dem7" not in off:
        return result(gate)
    if (
        not fv5_authenticated(protocol_input["recordRead"], protocol_input, off,
                              protocol_input["signedEvidence"]["txRef"])
        and "delivery-requires-authenticated-record" not in off
    ):
        return result("indeterminate")
    # The FV gate's bft-final half, verified here rather than taken from a
    # caller's verdict: delivery never rests on a block that is not final.
    if not presented_final(protocol_input["recordRead"], protocol_input,
                           "delivery-requires-bft-final-inclusion", off):
        return result("indeterminate")
    # The FV gate is the FV-5 result and bft-final inclusion verified above,
    # never a caller's verdict; SB-1 and PB compose as given.
    for name in ("sb1", "pb"):
        verdict = protocol_input["otherGates"][name]
        if verdict != "pass" and f"delivery-requires-{name}" not in off:
            return result(verdict)
    tuple_ = {
        "jobId": protocol_input["phase"]["jobId"],
        "phaseIndex": protocol_input["phase"]["phaseIndex"],
    }
    # The payee's history is the snapshot of its durable admission index read
    # for this check. A presented list that omits or adds an admission, as a
    # restart with process-local history would, is not that history.
    admissions = protocol_input["consumerAdmissions"]
    index = protocol_input.get("admissionIndex")
    if not admission_index(index, off):
        if "delivery-requires-admission-index" not in off:
            return result("error")
    elif history(admissions) != history(index["admissions"]) and "delivery-history-is-admission-index" not in off:
        return result("error")
    # SB-1 projects every admitted reference before SB-2 compares; one that
    # cannot project is malformed. A Demos reference has no legacy spelling.
    presented = demos_id(protocol_input["signedEvidence"]["txRef"], off)
    keys = [demos_id(admitted.get("txRef"), off) for admitted in admissions]
    if (presented is None or None in keys) and "sb2-admitted-malformed-error" not in off:
        return result("error")
    others = [
        admitted for admitted, key in zip(admissions, keys)
        if key is not None and key == presented
        and ({k: admitted.get(k) for k in tuple_} != tuple_ or "sb2-same-tuple-idempotent" in off)
    ]
    if others and "delivery-sb2-own-admissions" not in off:
        return result("indeterminate")
    return result("pass")


def demos_id(reference, off):
    if not (isinstance(reference, dict) and set(reference) == {"kind", "txHash", "blockNumber"}
            and reference["kind"] == "demos" and _safe_integer(reference["blockNumber"])):
        return None
    value = reference["txHash"]
    if not isinstance(value, str):
        return None
    if "sb1-demos-shape" in off:
        return "demos:" + value
    if "sb1-demos-canonical" in off:
        value = value.removeprefix("0x").lower()
    if not HASH.fullmatch(value):
        return None
    return "demos:" + (str(reference["blockNumber"]) if "sb1-demos-id" in off else value)


def project_id(protocol_input, off):
    key = demos_id(protocol_input["txRef"], off)
    return ("pass" if key else "error"), {"settlementTxId": key}


def resolve_group(protocol_input, off):
    """SB-2 over the presented records only: settlement accounting and the
    DACS-5 derivation never add the consumer's other admissions."""
    records = protocol_input["records"]
    if "sb2-presented-set-only" in off:
        # The wrong implementation adds its own earlier admissions, so its
        # result cannot be reproduced from the presented set.
        records = records + protocol_input["consumerAdmissions"]
    keys = [demos_id(record["txRef"], off) for record in records]
    if None in keys:
        return "error", {"records": []}
    groups = {}
    for record, key in zip(records, keys):
        group = (key, record["jobId"]) if "sb2-group-raw-references" in off else key
        groups.setdefault(group, set()).add((record["jobId"], record["phaseIndex"]))
    decisions = [
        "indeterminate" if len(groups[(key, record["jobId"]) if "sb2-group-raw-references" in off else key]) > 1 else "pass"
        for record, key in zip(records, keys)
    ]
    return ("indeterminate" if "indeterminate" in decisions else "pass"), {
        "records": [{"settlementTxId": key, "decision": decision} for key, decision in zip(keys, decisions)]}


OPERATIONS = {
    "classify-execution": classify,
    "resume-phase": resume,
    "apr-reconciliation-evidence": apr_evidence,
    "pre-sign-gate": pre_sign_gate,
    "rail-preflight": rail_preflight,
    "broadcast-gate": broadcast_gate,
    "classify-egress-outcome": egress_outcome,
    "admit-evidence": admit,
    "admit-for-delivery": admit_for_delivery,
    "project-settlement-id": project_id,
    "resolve-settlement-group": resolve_group,
}


def evaluate(vector: dict, off=frozenset()) -> tuple[str, dict]:
    return OPERATIONS[vector["operation"]](vector["protocolInput"], frozenset(off))


def flipping_guards(vector: dict) -> list[str]:
    baseline = evaluate(vector)
    return sorted(guard for guard in GUARDS if evaluate(vector, {guard}) != baseline)


class PayDemExecutionVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.data = generator.load_vectors(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {vector["name"]: vector for vector in cls.data["vectors"]}

    def test_committed_file_is_deterministic(self):
        self.assertEqual(VECTORS.read_text(encoding="utf-8"), generator.rendered())

    def test_corpus_hash_is_jcs_bound_and_names_are_unique(self):
        encoded = canonicalize(self.raw["vectors"]).encode("utf-8")
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), self.data["hash"])
        self.assertEqual(self.data["count"], len(self.data["vectors"]))
        self.assertEqual(self.data["count"], len(self.cases))
        # Every vector survives a JCS round trip unchanged, so a JavaScript
        # JSON.parse reader sees the same values as this oracle.
        for vector in self.raw["vectors"]:
            with self.subTest(name=vector["name"]):
                self.assertEqual(vector, json.loads(canonicalize(vector)))

    def test_member_order_survives_a_member_sorting_round_trip(self):
        """Member order is part of a signed transaction's, a validity
        response's and a record's meaning, and JSON objects are unordered for
        a generic reader. The corpus carries those members as exact JSON
        text, which its JCS hash covers: a JCS round trip of the corpus, as
        any member-sorting reader performs, changes no vector's result. At
        f47edff, with those members as objects, it changed 58 results."""
        def exact_members(value):
            if isinstance(value, list):
                for item in value:
                    yield from exact_members(item)
            elif isinstance(value, dict):
                for key, item in value.items():
                    if key in generator.EXACT_JSON_MEMBERS:
                        yield item
                    else:
                        yield from exact_members(item)
        members = list(exact_members(self.raw["vectors"]))
        self.assertGreater(len(members), 400)
        self.assertTrue(all(isinstance(member, str) for member in members))
        sorted_text = json.dumps(dict(self.raw, vectors=json.loads(canonicalize(self.raw["vectors"]))))
        round_trip = generator.load_vectors(sorted_text)
        self.assertEqual(self.data["hash"], hashlib.sha256(
            canonicalize(json.loads(sorted_text)["vectors"]).encode("utf-8")).hexdigest())
        for vector, other in zip(self.data["vectors"], round_trip["vectors"]):
            with self.subTest(name=vector["name"]):
                self.assertEqual((vector["expected"], vector["want"]), evaluate(other))
        # Without the exact text, the same round trip reorders a signed
        # transaction's content and the authentic transfer no longer verifies.
        transaction = self.cases["confirm-after-durable-retention"]["protocolInput"]["signedTransaction"]
        self.assertTrue(authentic(transaction))
        self.assertFalse(authentic(json.loads(canonicalize(transaction))))

    def test_cli_check_accepts_the_committed_file_and_rejects_a_stale_one(self):
        ok = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(0, ok.returncode, ok.stdout + ok.stderr)
        self.assertIn(f"OK ({self.data['count']} vectors)", ok.stdout)
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "scripts").mkdir()
            for name in ("generate_pay_dem_execution_vectors.py", "jcs.py", "demos_json.py",
                         "settlement_finality_reference.py"):
                shutil.copy(ROOT / "scripts" / name, root / "scripts" / name)
            output = root / "conformance/vectors/security/pay-dem-execution-v0.1.json"
            output.parent.mkdir(parents=True)
            output.write_text(VECTORS.read_text(encoding="utf-8").replace('"pass"', '"fail"', 1), encoding="utf-8")
            script = root / "scripts/generate_pay_dem_execution_vectors.py"
            stale = subprocess.run(
                [sys.executable, str(script), "--check"],
                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(1, stale.returncode, stale.stdout + stale.stderr)
            self.assertIn("stale", stale.stdout)
            output.unlink()
            missing = subprocess.run(
                [sys.executable, str(script), "--check"],
                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(1, missing.returncode, missing.stdout + missing.stderr)
            written = subprocess.run(
                [sys.executable, str(script), "--write"],
                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(0, written.returncode, written.stdout + written.stderr)
            self.assertEqual(VECTORS.read_text(encoding="utf-8"), output.read_text(encoding="utf-8"))

    def test_every_vector_executes_to_its_pinned_result(self):
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                expected, want = evaluate(vector)
                self.assertEqual(vector["expected"], expected)
                self.assertEqual(vector["want"], want)

    def test_handler_results_use_pc4_classes(self):
        for vector in self.data["vectors"]:
            if vector["operation"] not in {"classify-execution", "resume-phase"}:
                continue
            with self.subTest(name=vector["name"]):
                self.assertEqual(HANDLER_WANT[vector["expected"]], vector["want"])
                self.assertIn(vector["want"]["errorClass"], {None, "permanent", "substrate"})

    def test_every_vector_fails_when_each_named_guard_is_removed(self):
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                self.assertTrue(vector["guards"], "every vector names a guard")
                self.assertEqual(vector["guards"], flipping_guards(vector))

    def test_every_guard_is_load_bearing(self):
        named = {guard for vector in self.data["vectors"] for guard in vector["guards"]}
        self.assertEqual(GUARDS, named)

    def test_every_dem_rule_is_defined_and_exercised(self):
        spec = SPEC.read_text(encoding="utf-8")
        defined = {int(n) for n in re.findall(r"\(DEM-(\d+)\)", spec)}
        self.assertEqual(set(range(1, 8)), defined)
        cited = set()
        for vector in self.data["vectors"]:
            cited.update(int(n) for n in re.findall(r"DEM-(\d+)", vector["rule"]))
        self.assertEqual(defined, cited)

    def test_live_node2_records_classify_by_their_recorded_status(self):
        self.assertEqual("indeterminate", evaluate(self.cases["node2-confirmed-record"])[0])
        # The live failed record read by plain RPC is unresolved; the same
        # record authenticated under FV-5 is the DEM-4 terminal failure.
        self.assertEqual("indeterminate", evaluate(self.cases["node2-included-failed-record"])[0])
        self.assertNotIn("executionResult", self.cases["node2-included-failed-record"]["protocolInput"]["recordRead"])
        self.assertEqual("fail", evaluate(self.cases["node2-failed-record-authenticated"])[0])
        self.assertEqual(self.cases["node2-included-failed-record"]["protocolInput"]["recordRead"]["record"],
                         self.cases["node2-failed-record-authenticated"]["protocolInput"]["recordRead"]["record"])
        self.assertEqual("included", self.cases["node2-included-failed-record"]["protocolInput"]["statusIndex"])
        # The same live records, retained in raw wire types instead of the
        # profile projection, would never bind.
        raw = dict(self.cases["node2-confirmed-record"]["protocolInput"])
        record = raw["recordRead"]["record"]
        raw["retainedTransfer"] = dict(
            raw["retainedTransfer"], nonce=record["content"]["nonce"], amountOs=record["content"]["amount"],
        )
        self.assertEqual("indeterminate", classify(raw, frozenset())[0])

    def test_status_index_uses_node_labels(self):
        labels = {vector["protocolInput"].get("statusIndex") for vector in self.data["vectors"]}
        self.assertEqual({None, "included", "pending", "unknown"}, labels)

    def test_inclusion_alone_never_succeeds_or_authorizes(self):
        for vector in self.data["vectors"]:
            if vector["operation"] in {"pre-sign-gate", "rail-preflight", "broadcast-gate", "project-settlement-id",
                                       "resolve-settlement-group", "apr-reconciliation-evidence",
                                       "classify-egress-outcome"}:
                continue
            read = vector["protocolInput"]["recordRead"]
            record = read.get("record") if read.get("state") == "found" else None
            if isinstance(record, dict) and record.get("status") == "confirmed":
                continue
            with self.subTest(name=vector["name"]):
                self.assertNotEqual("pass", vector["expected"])
                self.assertFalse(vector["want"].get("deliveryAuthorized"))

    def test_dem7_alone_never_authorizes_delivery(self):
        for vector in self.data["vectors"]:
            if vector["operation"] == "admit-evidence":
                with self.subTest(name=vector["name"]):
                    self.assertFalse(vector["want"]["deliveryAuthorized"])
        delivered = {
            vector["name"] for vector in self.data["vectors"]
            if vector["want"].get("deliveryAuthorized") or vector["want"].get("settlementAccounting")
        }
        self.assertEqual({"delivery-after-all-gates", "delivery-same-tuple-readmitted", "delivery-to-0x-payee-address",
                          "delivery-to-did-payee-address", "delivery-from-0x-paying-key",
                          "delivery-fv-form-result", "delivery-fv-form-result-self-reported-node",
                          "delivery-fv-form-result-reordered-edit-members"}, delivered)
        for name in delivered:
            protocol_input = self.cases[name]["protocolInput"]
            self.assertTrue(fv5_authenticated(protocol_input["recordRead"], protocol_input, frozenset()))
            # The FV gate is verified from the evidence, never a caller verdict.
            self.assertEqual({"sb1": "pass", "pb": "pass"}, protocol_input["otherGates"])

    def test_raw_demos_references_group_before_any_member_counts(self):
        collision = self.cases["sb2-demos-two-job-collision"]
        self.assertEqual("indeterminate", evaluate(collision)[0])
        self.assertEqual(["indeterminate", "indeterminate"],
                         [record["decision"] for record in evaluate(collision)[1]["records"]])
        reverse = dict(collision, protocolInput={"records": list(reversed(collision["protocolInput"]["records"]))})
        self.assertEqual(evaluate(collision), evaluate(reverse))
        self.assertEqual("pass", evaluate(self.cases["sb2-demos-distinct-hash-control"])[0])

    def test_handler_success_authorizes_no_delivery_or_accounting(self):
        # DEM-3 success is the payer's result; delivery and settlement
        # accounting come only from the consumer's composed admission.
        successes = [
            vector for vector in self.data["vectors"]
            if vector["operation"] in {"classify-execution", "resume-phase"} and vector["expected"] == "pass"
        ]
        self.assertTrue(successes)
        for vector in successes:
            with self.subTest(name=vector["name"]):
                self.assertTrue(vector["want"]["ok"])
                self.assertFalse(vector["want"]["deliveryAuthorized"])
                self.assertFalse(vector["want"]["settlementAccounting"])
                self.assertIn("success-authorizes-no-delivery", vector["guards"])

    def test_broadcast_requires_an_authentic_signed_transaction(self):
        control = self.cases["first-broadcast-after-durable-retention"]["protocolInput"]
        self.assertTrue(authentic(control["signedTransaction"]))
        self.assertEqual(control["signedTransaction"]["hash"], control["retainedTransfer"]["txHash"])
        forged = {
            "broadcast-unsigned-transaction",
            "broadcast-hash-not-over-content",
            "broadcast-signed-by-another-key",
            "broadcast-signature-type-not-ed25519",
        }
        # Valid signatures in another spelling: only the exact form refuses them.
        respelled = {
            "broadcast-signature-uppercase-hex",
            "broadcast-signature-unprefixed-hex",
            "broadcast-signature-extra-member",
        }
        # The digest in upper case, signed as spelled: only the exact hash form refuses it.
        hash_respelled = {"broadcast-hash-uppercase"}
        for vector in self.data["vectors"]:
            if vector["operation"] != "broadcast-gate":
                continue
            with self.subTest(name=vector["name"]):
                signed_tx = vector["protocolInput"]["signedTransaction"]
                self.assertEqual(vector["name"] not in forged | respelled | hash_respelled, authentic(signed_tx))
                if vector["name"] in hash_respelled:
                    self.assertTrue(authentic(signed_tx, {"signed-hash-form"}))
                    self.assertEqual(signed_tx["hash"].lower(), vector["protocolInput"]["retainedTransfer"]["txHash"])
                    self.assertEqual(["signed-hash-form"], vector["guards"])
                    self.assertEqual("fail", vector["expected"])
                if vector["name"] in forged:
                    # Every other DEM-1 value agrees, so only authentication refuses it.
                    self.assertEqual(["signed-transaction-authentic"], vector["guards"])
                    self.assertEqual("fail", vector["expected"])
                if vector["name"] in respelled:
                    self.assertTrue(authentic(signed_tx, {"signed-signature-form"}))
                    self.assertEqual(["signed-signature-form", "signed-transaction-authentic"], vector["guards"])
                    self.assertEqual("fail", vector["expected"])
        # The live node2 records carry demosdk signatures in the same scheme.
        for name in ("node2-confirmed-record", "node2-included-failed-record"):
            record = self.cases[name]["protocolInput"]["recordRead"]["record"]
            sender = bytes.fromhex(record["content"]["from"][2:])
            Ed25519PublicKey.from_public_bytes(sender).verify(
                bytes.fromhex(record["signature"]["data"][2:]), record["hash"].encode("utf-8")
            )

    def test_permitted_broadcast_is_a_complete_sdk_envelope(self):
        # demosdk 4.0.16 pay() and sign() add timestamp, node fees and
        # regenerated edits before hashing; the pinned node refuses a send
        # without them.
        content = self.cases["first-broadcast-after-durable-retention"]["protocolInput"]["signedTransaction"]["content"]
        self.assertEqual(
            ["type", "from", "to", "amount", "data", "nonce", "timestamp", "transaction_fee",
             "from_ed25519_address", "gcr_edits"],
            list(content),
        )
        self.assertTrue(_safe_integer(content["timestamp"]) and isinstance(content["timestamp"], int))
        self.assertEqual(FEE_MEMBERS, list(content["transaction_fee"]))
        self.assertTrue(edits_match(content))
        # The regeneration reproduces the edits SDK clients shipped in both
        # live node2 records, member order and types included.
        for name in ("node2-confirmed-record", "node2-included-failed-record"):
            with self.subTest(name=name):
                served = self.cases[name]["protocolInput"]["recordRead"]["record"]["content"]
                self.assertTrue(edits_match(served))
        permitted = [vector["name"] for vector in self.data["vectors"] if vector["want"].get("broadcastPermitted")]
        self.assertEqual(["first-broadcast-after-durable-retention", "broadcast-prefixed-send-argument",
                          "broadcast-signed-nonce-integer-valued-number",
                          "broadcast-with-rail-network-entry-among-several",
                          "broadcast-to-0x-payee-address", "broadcast-to-did-payee-address",
                          "broadcast-from-did-paying-key", "confirm-from-key-claim-paying-key",
                          "broadcast-from-key-claim-paying-key", "confirm-after-durable-retention",
                          "broadcast-completes-own-confirm"], permitted)
        for name in permitted:
            with self.subTest(name=name):
                signed_content = self.cases[name]["protocolInput"]["signedTransaction"]["content"]
                if name == "broadcast-prefixed-send-argument":
                    # demosdk passes a 0x-prefixed send argument through; the
                    # credit edit names the same account as the control.
                    self.assertEqual("0x" + generator.PAYEE_KEY, signed_content["data"][1]["args"][0])
                    self.assertEqual(content["gcr_edits"], signed_content["gcr_edits"])
                    self.assertEqual({k: v for k, v in content.items() if k != "data"},
                                     {k: v for k, v in signed_content.items() if k != "data"})
                    continue
                self.assertEqual(content, signed_content)

    def test_each_missing_or_misshaped_envelope_member_is_refused(self):
        control = self.cases["first-broadcast-after-durable-retention"]
        for name, guard in (
            ("fee-object-missing", "signed-os-strings"),
            ("fee-member-missing", "signed-os-strings"),
            ("numeric-rpc-fee", "signed-os-strings"),
            ("numeric-additional-fee", "signed-os-strings"),
            ("noncanonical-fee-string", "signed-os-strings"),
            ("fee-members-reordered", "signed-fee-members"),
            ("rpc-address-omitted", "signed-fee-members"),
            ("extra-fee-member", "signed-fee-members"),
            ("numeric-rpc-address", "signed-fee-members"),
            ("string-nonce", "signed-nonce-integer"),
            ("timestamp-missing", "signed-timestamp"),
            ("fractional-timestamp", "signed-timestamp"),
            ("timestamp-zero", "signed-timestamp"),
            ("negative-timestamp", "signed-timestamp"),
            ("string-timestamp", "signed-timestamp"),
            ("ed25519-address-missing", "signed-ed25519-address"),
            ("ed25519-address-mismatch", "decode-address"),
            ("edits-missing", "signed-native-edits"),
            ("edits-credit-differs", "signed-native-edits"),
            ("edits-extra-credit", "signed-native-edits"),
        ):
            with self.subTest(name=name):
                case = self.cases["broadcast-signed-" + name]
                self.assertTrue(authentic(case["protocolInput"]["signedTransaction"]))
                self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(case))
                self.assertEqual(("pass", {"broadcastPermitted": True}), evaluate(case, {guard}))
                self.assertEqual(evaluate(control), evaluate(control, {guard}))

    def test_every_signed_transaction_must_has_a_rejecting_vector(self):
        # Each MUST of DEMOS-MAPPING §A.2 *Signed transaction* names vectors
        # that are refused and pass once the named guard alone is removed. A
        # new MUST there without a witness fails the count.
        demos = DEMOS.read_text(encoding="utf-8")
        start = demos.index("*Signed transaction.*")
        section = demos[start:demos.index("*Applied payment authority.*", start)]
        os_strings = [("broadcast-signed-" + name, "signed-os-strings") for name in (
            "numeric-os-amount", "numeric-os-fee", "numeric-rpc-fee", "numeric-additional-fee", "noncanonical-fee-string")]
        timestamp = [("broadcast-signed-" + name, "signed-timestamp") for name in (
            "timestamp-missing", "fractional-timestamp", "timestamp-zero", "negative-timestamp", "string-timestamp")]
        address = [("broadcast-signed-ed25519-address-missing", "signed-ed25519-address")]
        edits = [("broadcast-signed-" + name, "signed-native-edits") for name in (
            "edits-missing", "edits-credit-differs", "edits-extra-credit")]
        witnesses = {
            "MUST be canonical OS decimal strings": os_strings,
            "The fee object and those three members MUST be present": [
                ("broadcast-signed-fee-object-missing", "signed-os-strings"),
                ("broadcast-signed-fee-member-missing", "signed-os-strings"),
            ],
            "Signed `content.nonce` MUST be a JSON integer": [("broadcast-signed-string-nonce", "signed-nonce-integer")],
            "The fee object MUST have exactly the members": [("broadcast-signed-" + name, "signed-fee-members") for name in (
                "fee-members-reordered", "rpc-address-omitted", "extra-fee-member", "numeric-rpc-address")],
            "The content MUST also carry the members": [timestamp[0], *address, edits[0]],
            "`timestamp` MUST be a positive JSON integer": timestamp,
            "`content.from_ed25519_address` MUST be present": address,
            "`gcr_edits` MUST equal the four edits": edits,
            "`hash` MUST be the lower-case hexadecimal SHA-256": [
                ("broadcast-hash-not-over-content", "signed-transaction-authentic"),
                ("broadcast-hash-uppercase", "signed-hash-form")],
            "`signature` MUST be `{\"type\": \"ed25519\"": [
                ("broadcast-unsigned-transaction", "signed-transaction-authentic"),
                ("broadcast-signature-type-not-ed25519", "signed-transaction-authentic"),
                ("broadcast-signed-by-another-key", "signed-transaction-authentic"),
                ("broadcast-signature-uppercase-hex", "signed-signature-form"),
                ("broadcast-signature-unprefixed-hex", "signed-signature-form"),
                ("broadcast-signature-extra-member", "signed-signature-form"),
            ],
        }
        self.assertEqual(section.count("MUST"), len(witnesses))
        control = self.cases["first-broadcast-after-durable-retention"]
        for phrase, cases in witnesses.items():
            self.assertIn(phrase, section)
            for name, guard in cases:
                with self.subTest(name=name):
                    vector = self.cases[name]
                    self.assertEqual(("broadcast-gate", "fail"), (vector["operation"], vector["expected"]))
                    self.assertIn(guard, vector["guards"])
                    self.assertEqual(("pass", {"broadcastPermitted": True}), evaluate(vector, {guard}))
                    self.assertEqual(evaluate(control), evaluate(control, {guard}))

    def test_dem1_is_checked_at_the_first_egress_of_the_signed_bytes(self):
        # demosdk confirm (confirmTx) sends the whole signed transaction to a
        # node, so DEM-1 holds before it and DEM-6 starts there.
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("The signed transaction's *first egress* is the first call that carries it out of the handler", spec)
        self.assertIn("`confirm` (`confirmTx`) validity request that precedes `broadcast`", spec)
        self.assertIn("Before the first egress, the handler MUST durably retain", spec)
        self.assertIn("The retained transfer may have been broadcast from its first egress on", spec)
        self.assertNotIn("Before the first broadcast, the handler MUST durably retain", spec)
        # sign -> confirm -> journal -> broadcast: the confirm happens before durable retention.
        early = self.cases["confirm-before-durable-retention"]
        self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(early))
        self.assertEqual(("pass", {"broadcastPermitted": True}), evaluate(early, {"retention-before-first-egress"}))
        self.assertEqual(("pass", {"broadcastPermitted": True}), evaluate(self.cases["confirm-after-durable-retention"]))
        # A timeout, error or restart after confirm leaves only re-reads.
        for name, guard in (("rebroadcast-after-interrupted-confirm-refused", "no-rebroadcast"),
                            ("replacement-after-interrupted-confirm-refused", "no-replacement")):
            with self.subTest(name=name):
                case = self.cases[name]
                self.assertEqual("confirm-sent-interrupted", case["protocolInput"]["broadcastState"])
                self.assertEqual("fail", evaluate(case)[0])
                self.assertEqual("pass", evaluate(case, {"confirm-egress-may-broadcast"})[0])
                self.assertEqual("pass", evaluate(case, {guard})[0])
        # Only the broadcast that completes the uninterrupted submission follows a confirm.
        own = self.cases["broadcast-completes-own-confirm"]
        self.assertEqual("pass", evaluate(own)[0])
        self.assertEqual("fail", evaluate(own, {"submission-completes-own-confirm"})[0])
        for request in ("confirm-retained", "broadcast-replacement"):
            with self.subTest(request=request):
                again = json.loads(json.dumps(own))
                again["protocolInput"]["request"] = request
                self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(again))
        # An unknown state fails closed.
        unknown = json.loads(json.dumps(self.cases["first-broadcast-after-durable-retention"]))
        unknown["protocolInput"]["broadcastState"] = "confirm-timed-out"
        self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(unknown))

    def test_broadcast_carries_this_submissions_validity_response(self):
        # demosdk 4.0.16 broadcast(validationData) sends the confirm result and
        # the pinned node executes response.data.transaction, so DEM-1 binds
        # that payload to the retained transfer and DEM-6 to this submission.
        spec = SPEC.read_text(encoding="utf-8")
        demos = DEMOS.read_text(encoding="utf-8")
        self.assertIn("A demosdk `broadcast` does not carry the retained transaction", spec)
        self.assertIn("carries exactly the validity response that the same submission's `confirm` returned", spec)
        self.assertIn("*Validity response.*", demos)
        self.assertIn("the node executes the embedded transaction", demos)
        control = self.cases["first-broadcast-after-durable-retention"]
        value = control["protocolInput"]
        response = value["validityResponse"]
        # The real RPCResponseWithValidityData shape, signed by the node key.
        self.assertEqual(["result", "response", "require_reply", "extra"], list(response))
        self.assertEqual(200, response["result"])
        self.assertEqual(["data", "signature", "rpc_public_key"], list(response["response"]))
        data = response["response"]["data"]
        self.assertEqual(["valid", "reference_block", "message", "gas_operation", "transaction"], list(data))
        self.assertIs(True, data["valid"])
        rpc_key = response["response"]["rpc_public_key"]
        self.assertEqual("ed25519", rpc_key["type"])
        digest = hashlib.sha256(stringify(data).encode("utf-8")).hexdigest()
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(rpc_key["data"][2:])).verify(
            bytes.fromhex(response["response"]["signature"]["data"][2:]), digest.encode("utf-8"))
        for member in ("content", "hash", "signature"):
            self.assertEqual(value["signedTransaction"][member], data["transaction"][member])
        self.assertEqual(response, value["confirmResponse"])
        # Every broadcast carries a validity response; a confirm, and any
        # other route that carries the signed transaction, carries no response.
        for vector in self.data["vectors"]:
            if vector["operation"] != "broadcast-gate":
                continue
            with self.subTest(payload=vector["name"]):
                inputs = vector["protocolInput"]
                if not inputs["request"].startswith("broadcast-"):
                    self.assertEqual((None, None), (inputs["confirmResponse"], inputs["validityResponse"]))
                elif vector["name"] != "broadcast-validity-response-missing":
                    self.assertIsInstance(inputs["validityResponse"], dict)
        # Missing, stale, other-transaction, refused and re-serialized
        # responses differ from the control only there, and only the payload
        # check refuses them.
        responses = {"confirmResponse", "validityResponse"}
        for name, guard in (
            ("broadcast-validity-response-missing", "broadcast-carries-own-validity-response"),
            ("broadcast-stale-validity-response", "broadcast-carries-own-validity-response"),
            ("broadcast-validity-response-other-transaction", "validity-response-binds-retained-transfer"),
            ("broadcast-validity-response-other-nonce", "validity-response-binds-retained-transfer"),
            ("broadcast-validity-response-not-valid", "validity-response-binds-retained-transfer"),
            ("broadcast-validity-response-resigned-content", "validity-response-binds-retained-transfer"),
        ):
            with self.subTest(name=name):
                case = self.cases[name]
                self.assertEqual({k: v for k, v in value.items() if k not in responses},
                                 {k: v for k, v in case["protocolInput"].items() if k not in responses})
                self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(case))
                self.assertEqual([guard], case["guards"])
                self.assertEqual(("pass", {"broadcastPermitted": True}), evaluate(case, {guard}))
        other = self.cases["broadcast-validity-response-other-transaction"]["protocolInput"]["confirmResponse"]
        self.assertTrue(authentic(other["response"]["data"]["transaction"]))
        # A broadcast without a confirm of its own has no response to carry,
        # whatever response it holds.
        for held in (response, None):
            with self.subTest(no_confirm=held is not None):
                case = json.loads(json.dumps(control))
                case["protocolInput"].update(broadcastState="never-broadcast", confirmResponse=None, validityResponse=held)
                self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(case))

        def broken(change):
            case = json.loads(json.dumps(control))
            change(case["protocolInput"]["confirmResponse"])
            case["protocolInput"]["validityResponse"] = case["protocolInput"]["confirmResponse"]
            return case

        # Malformed or refusing responses fail closed.
        for label, change in (
            ("result-400", lambda r: r.update(result=400)),
            ("valid-string", lambda r: r["response"]["data"].update(valid="true")),
            ("valid-missing", lambda r: r["response"]["data"].pop("valid")),
            ("transaction-missing", lambda r: r["response"]["data"].pop("transaction")),
            ("transaction-null", lambda r: r["response"]["data"].update(transaction=None)),
            ("rpc-key-missing", lambda r: r["response"].pop("rpc_public_key")),
            ("signature-missing", lambda r: r["response"].pop("signature")),
            ("response-not-object", lambda r: r.update(response="ok")),
            ("embedded-hash-uppercase", lambda r: r["response"]["data"]["transaction"].update(
                hash=r["response"]["data"]["transaction"]["hash"].upper())),
            ("embedded-signature-dropped", lambda r: r["response"]["data"]["transaction"].pop("signature")),
        ):
            with self.subTest(malformed=label):
                self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(broken(change)))
        # The SDK envelope members the profile ignores do not matter.
        extra = broken(lambda r: r["response"]["data"]["transaction"].update(status="pending", ed25519_signature=None))
        self.assertEqual(("pass", {"broadcastPermitted": True}), evaluate(extra))
        # The carried response must be the own response, member order included.
        reordered = json.loads(json.dumps(control))
        own = reordered["protocolInput"]["confirmResponse"]
        reordered["protocolInput"]["validityResponse"] = dict(reversed(list(own.items())))
        self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(reordered))

    def test_fee_separated_network_is_outside_the_profile(self):
        # With gasFeeSeparation active the pinned node stores fee edits before
        # the send's four, so DEM-3 never passes: DEM-1 refuses to sign there,
        # and such a record stays indeterminate on both read paths even though
        # the authority reports the payment applied and its last four edits
        # are the send's.
        demos = DEMOS.read_text(encoding="utf-8")
        self.assertIn("the `gasFeeSeparation` fork is unscheduled: the network's sealed genesis sets "
                      "`forks.gasFeeSeparation.activationHeight` to `null`", demos)
        self.assertIn("MUST therefore attest, for each network, from that network's sealed genesis, "
                      "that `gasFeeSeparation` is unscheduled", demos)
        self.assertIn("A record whose edits carry fee-distribution edits is outside this profile", demos)
        served = generator.served_edits(generator.send_content(), generator.TX_HASH)
        for name in ("confirmed-fee-separated-edits", "consumer-fee-separated-edits"):
            with self.subTest(name=name):
                vector = self.cases[name]
                read = vector["protocolInput"]["recordRead"]
                edits = read["record"]["content"]["gcr_edits"]
                self.assertGreater(len(edits), 4)
                self.assertEqual(served, edits[-4:])
                self.assertEqual(generator.committed_change(generator.APPLIED),
                                 (read["appliedTransfer"]["payerDebitOs"], read["appliedTransfer"]["payeeCreditOs"]))
                self.assertEqual("indeterminate", evaluate(vector)[0])
                # A verifier that accepts any edit list ending in the send's
                # four would count this payment.
                self.assertEqual("pass", evaluate(vector, {"confirmed-requires-send-edits"})[0])

    def test_no_debit_without_pinned_node_and_applied_payment_authority(self):
        # DEM-3 success needs both, so DEM-1 refuses to sign or send without them.
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("The handler MUST NOT sign or broadcast a transfer unless its Demos binding configures", spec)
        self.assertIn("Demos binding without pinned nodes, an applied-payment authority, a genesis attestation that "
                      "`gasFeeSeparation` is unscheduled, `bft-final` trust that covers the rail's profile or an FV-5 "
                      "execution-result policy, found at settle → `substrate`", spec)
        self.assertIn("every input a final verdict on the transfer consumes", spec)
        self.assertIn("The handler's re-reads verify under those same members", spec)
        # Balance is permanent only before the first egress; a confirm refusal
        # after it leaves the signed bytes at a node, so it is DEM-5 substrate.
        self.assertIn("payer DEM balance insufficient before the first egress (no `confirm` or broadcast has carried "
                      "the signed transfer) → `permanent`", spec)
        self.assertIn("a `confirm` that refuses the transfer after its first egress, for example for insufficient "
                      "balance → `substrate`", spec)
        self.assertNotIn("payer DEM balance insufficient before broadcast", spec)
        self.assertIn("| `pay-dem` | Not reference-backed", spec)
        self.assertIn("so DEM-1 refuses to sign or send a transfer under it", DEMOS.read_text(encoding="utf-8"))
        fee_scope = "broadcast-requires-gas-fee-separation-unscheduled"
        for name, guard in (("broadcast-without-applied-payment-authority", "broadcast-requires-applied-payment-authority"),
                            ("confirm-without-applied-payment-authority", "broadcast-requires-applied-payment-authority"),
                            ("broadcast-without-pinned-node", "broadcast-requires-pinned-node"),
                            ("broadcast-with-gas-fee-separation-scheduled", fee_scope),
                            ("confirm-with-gas-fee-separation-scheduled", fee_scope),
                            ("broadcast-without-fork-attestation", fee_scope)):
            with self.subTest(name=name):
                self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(self.cases[name]))
                self.assertEqual(("pass", {"broadcastPermitted": True}), evaluate(self.cases[name], {guard}))
        # Each refused fork-scope vector differs from its passing control in
        # that binding member alone.
        for name, control in (("broadcast-with-gas-fee-separation-scheduled", "first-broadcast-after-durable-retention"),
                              ("confirm-with-gas-fee-separation-scheduled", "confirm-after-durable-retention"),
                              ("broadcast-without-fork-attestation", "first-broadcast-after-durable-retention")):
            with self.subTest(control=control, name=name):
                refused = json.loads(json.dumps(self.cases[name]["protocolInput"]))
                passing = json.loads(json.dumps(self.cases[control]["protocolInput"]))
                refused["demosBinding"][0].pop("gasFeeSeparation", None)
                self.assertIsNone(passing["demosBinding"][0].pop("gasFeeSeparation")["activationHeight"])
                self.assertEqual(passing, refused)
        # A missing, malformed or other-network member fails closed.
        for member in BINDING:
            for value in (None, True, "true", 1, {}, dict(generator.NETWORK, extra="x"),
                          {"networkId": generator.NETWORK["networkId"]}, generator.OTHER_NETWORK):
                with self.subTest(member=member, value=value):
                    case = json.loads(json.dumps(self.cases["first-broadcast-after-durable-retention"]))
                    entry = case["protocolInput"]["demosBinding"][0]
                    if value is None:
                        del entry[member]
                    elif isinstance(value, dict) and member == "gasFeeSeparation" and value:
                        entry[member] = dict(value, activationHeight=None)
                    else:
                        entry[member] = value
                    self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(case))
        for vector in self.data["vectors"]:
            if vector["operation"] == "broadcast-gate" and vector["want"]["broadcastPermitted"]:
                with self.subTest(name=vector["name"]):
                    self.assertEqual(generator.NETWORK, vector["protocolInput"]["railNetwork"])
                    self.assertEqual(dict.fromkeys(BINDING, True), binding_members(vector["protocolInput"], frozenset()))
        # Before pay()/sign(): the RAV-R3 preflight checked the binding before
        # rail selection, so a refusal at settle is the RAV-R4 result ok false,
        # errorClass substrate, and there is no signed transaction to send.
        self.assertIn('the handler MUST return `ok: false` with `errorClass: "substrate"` before it signs', spec)
        refused = {"ok": False, "errorClass": "substrate", "signPermitted": False}
        presign = {name: vector for name, vector in self.cases.items() if vector["operation"] == "pre-sign-gate"}
        self.assertEqual({"sign-with-pinned-node-and-applied-payment-authority", "sign-without-pinned-node",
                          "sign-without-applied-payment-authority", "sign-with-gas-fee-separation-scheduled",
                          "sign-without-fork-attestation", "sign-without-binding",
                          "sign-without-bft-final-trust", "sign-with-bft-final-trust-without-rail-validator-set",
                          "sign-with-bft-final-trust-below-observation-threshold",
                          "sign-without-execution-result-policy", "sign-with-malformed-execution-result-policy",
                          "sign-with-unknown-execution-result-policy-kind",
                          "sign-with-rail-network-entry-among-several",
                          "sign-with-key-claim-paying-key", "sign-with-foreign-key-claim-listed",
                          "sign-with-key-claim-parameters-paying-key"}
                         | {"sign-with-" + suffix for suffix in (*NETWORK_VARIANTS, *UNUSABLE_TRUST)},
                         {name for name in presign if presign[name]["expected"] != "error"})
        # A party address that does not project is refused before signing,
        # PC-4 permanent, so no retention pins a phase that can never be paid.
        unpayable = {name for name in presign if presign[name]["expected"] == "error"}
        addresses = {"sign-payee-address-upper-case", "sign-payee-address-did-with-0x", "sign-payee-address-evm-length"}
        # A paying key that is no controlled Demos key claim of the retained
        # payer bundle is refused the same way (DEM-1): DEM-7 would not bind
        # its transfer, so the payment would execute and never be admitted.
        uncontrolled = {"sign-paying-key-" + suffix for suffix in (
            "listed-not-controlled", "session-key-presentation", "did-claim-only", "wrong-mechanism",
            "not-in-bundle", "claims-malformed")}
        self.assertEqual(addresses | uncontrolled | {"sign-paying-key-upper-case"}, unpayable)
        for name in unpayable:
            with self.subTest(name=name):
                self.assertEqual(("error", {"signPermitted": False, "ok": False, "errorClass": "permanent"}),
                                 evaluate(presign[name]))
                self.assertEqual(name in addresses,
                                 evaluate(presign[name], {"pre-sign-party-address-projects"})[0] == "pass")
                self.assertEqual(name in uncontrolled,
                                 evaluate(presign[name], {"pre-sign-paying-key-controlled"})[0] == "pass")
        for name, vector in presign.items():
            with self.subTest(name=name):
                self.assertEqual({"phase", "railNetwork", "finalityProfile", "demosBinding"},
                                 set(vector["protocolInput"]))
                self.assertEqual(generator.FINALITY_PROFILE, vector["protocolInput"]["finalityProfile"])
                self.assertEqual(generator.NETWORK, vector["protocolInput"]["railNetwork"])
                if vector["expected"] == "pass":
                    self.assertEqual(("pass", {"signPermitted": True, "ok": None, "errorClass": None}), evaluate(vector))
                    continue
                if vector["expected"] == "error":
                    continue  # the party-address refusals above
                self.assertEqual(("fail", refused), evaluate(vector))
                # A handler that blames the payer with permanent for a rail
                # that is not operational at settle (RAV-R4) fails the vector.
                self.assertEqual(("fail", dict(refused, errorClass="permanent")),
                                 evaluate(vector, {"binding-refusal-is-rail-unavailable"}))
        for name, guard in (("sign-without-pinned-node", "sign-requires-pinned-node"),
                            ("sign-without-applied-payment-authority", "sign-requires-applied-payment-authority"),
                            ("sign-with-gas-fee-separation-scheduled", "sign-requires-gas-fee-separation-unscheduled"),
                            ("sign-without-fork-attestation", "sign-requires-gas-fee-separation-unscheduled")):
            with self.subTest(name=name):
                self.assertTrue(evaluate(self.cases[name], {guard})[1]["signPermitted"])
        for member in BINDING:
            for value in (None, "true", 1, False, {}):
                with self.subTest(presign=member, value=value):
                    case = json.loads(json.dumps(presign["sign-with-pinned-node-and-applied-payment-authority"]))
                    if value is None:
                        del case["protocolInput"]["demosBinding"][0][member]
                    else:
                        case["protocolInput"]["demosBinding"][0][member] = value
                    self.assertEqual(("fail", refused), evaluate(case))
        # Without the rail's network, or with a malformed binding, no entry is
        # the rail's: nothing is signed.
        for change in ({"railNetwork": None}, {"railNetwork": {"networkId": generator.NETWORK["networkId"]}},
                       {"railNetwork": dict(generator.NETWORK, extra="x")}, {"demosBinding": None},
                       {"demosBinding": generator.binding_entry()}, {"demosBinding": ["x"]}):
            with self.subTest(presign=str(change)[:60]):
                case = json.loads(json.dumps(presign["sign-with-pinned-node-and-applied-payment-authority"]))
                for key, value in change.items():
                    if value is None:
                        del case["protocolInput"][key]
                    else:
                        case["protocolInput"][key] = value
                self.assertEqual(("fail", refused), evaluate(case))

    def test_binding_is_for_the_rail_network_at_every_gate(self):
        """DEM-1/RAV-R3 "for the phase's network": the rail's network is the
        pinned RailDefinition's consumerFinalityProfile.settlement, not the
        binding's. Each wrong-network binding, member or attestation is
        refused at sign, confirm, broadcast and preflight, and a gate that
        takes the network from its one binding signs where the record can
        never settle."""
        spec = SPEC.read_text(encoding="utf-8")
        demos = DEMOS.read_text(encoding="utf-8")
        self.assertIn("the phase's Demos network is the pinned `RailDefinition`'s "
                      "`consumerFinalityProfile.settlement` network", spec)
        self.assertIn("each member names that network and genesis", spec)
        self.assertIn("names that network's `networkId` and `genesisHash`", demos)
        operations = (("sign-with-", "pre-sign-gate"), ("confirm-with-", "broadcast-gate"),
                      ("broadcast-with-", "broadcast-gate"), ("preflight-live-rail-with-", "rail-preflight"))
        for suffix, guard in NETWORK_VARIANTS.items():
            for prefix, operation in operations:
                name = prefix + suffix
                with self.subTest(name=name):
                    vector = self.cases[name]
                    self.assertEqual(operation, vector["operation"])
                    self.assertEqual("fail", evaluate(vector)[0])
                    self.assertIn(guard, vector["guards"])
                    self.assertEqual(generator.NETWORK, vector["protocolInput"]["railNetwork"])
                    # Each one differs from its passing control only in the binding.
                    control = self.cases[{"sign-with-": "sign-with-pinned-node-and-applied-payment-authority",
                                          "confirm-with-": "confirm-after-durable-retention",
                                          "broadcast-with-": "first-broadcast-after-durable-retention",
                                          "preflight-live-rail-with-": "preflight-live-rail-with-binding"}[prefix]]
                    rest = {k: v for k, v in vector["protocolInput"].items() if k != "demosBinding"}
                    self.assertEqual({k: v for k, v in control["protocolInput"].items() if k != "demosBinding"}, rest)
                    self.assertEqual("pass", evaluate(control)[0])
                    self.assertNotEqual(control["protocolInput"]["demosBinding"],
                                        vector["protocolInput"]["demosBinding"])
        # A gate that keeps one global binding passes a binding for another
        # network; the one that looks the rail's entry up refuses it.
        global_binding = self.cases["sign-with-binding-for-another-network"]
        self.assertTrue(evaluate(global_binding, {"binding-network-is-rail-network"})[1]["signPermitted"])
        for name in ("sign-with-rail-network-entry-among-several", "broadcast-with-rail-network-entry-among-several",
                     "preflight-live-rail-with-rail-network-entry-among-several"):
            with self.subTest(name=name):
                entries = self.cases[name]["protocolInput"]["demosBinding"]
                self.assertNotEqual(generator.NETWORK, {k: entries[0][k] for k in NETWORK})
                self.assertEqual("pass", evaluate(self.cases[name])[0])
        # The classify, resume and admit paths bind the same rail network.
        for vector in self.data["vectors"]:
            if vector["operation"] in {"classify-execution", "resume-phase", "admit-evidence", "admit-for-delivery"}:
                with self.subTest(name=vector["name"]):
                    self.assertEqual(generator.NETWORK, vector["protocolInput"]["railNetwork"])
                    self.assertNotIn("network", vector["protocolInput"])

    def test_applied_payment_authority_binds_every_member_on_both_paths(self):
        # DEMOS-MAPPING §A.2: the authority binds the network, the inclusion
        # block identity, the transaction and block number, both parties and
        # the debit and credit, which are the change of the committed balances
        # it authenticates. Each member has a vector on the handler (DEM-3) and
        # the consumer (DEM-7) path that differs from the passing control in
        # that member alone (a debit or credit together with the balances it
        # is the change of) and does not pass.
        demos = DEMOS.read_text(encoding="utf-8")
        self.assertIn("The authority MUST bind the same network, inclusion block identity, transaction hash and block number", demos)
        for prefix, control_name, refused, figures_alone in (
            ("confirmed-applied-transfer-", "included-confirmed", "indeterminate",
             "confirmed-four-edits-authority-not-committed-change"),
            ("consumer-applied-transfer-", "consumer-confirmed-gate-passes", "fail",
             "consumer-four-edits-authority-not-committed-change"),
        ):
            control = self.cases[control_name]
            self.assertEqual("pass", evaluate(control)[0])
            proof = control["protocolInput"]["recordRead"]["appliedTransfer"]
            self.assertEqual(APPLIED_TRANSFER, set(proof))
            self.assertEqual(control["protocolInput"]["railNetwork"],
                             {k: proof[k] for k in ("networkId", "genesisHash")})
            self.assertEqual(control["protocolInput"]["inclusionObservation"]["blockId"], proof["blockId"])
            witnessed = set()
            for name, vector in self.cases.items():
                if not (name.startswith(prefix) or name == figures_alone):
                    continue
                varied = vector["protocolInput"]["recordRead"].get("appliedTransfer", {})
                differs = {k for k in APPLIED_TRANSFER if varied.get(k) != proof[k]}
                if (differs > {"committedBalances"}
                        and committed_change(varied) == (varied.get("payerDebitOs"), varied.get("payeeCreditOs"))):
                    differs.discard("committedBalances")
                rest = {k: v for k, v in vector["protocolInput"].items() if k != "recordRead"}
                read_rest = {k: v for k, v in vector["protocolInput"]["recordRead"].items() if k != "appliedTransfer"}
                if (len(differs) == 1
                        and rest == {k: v for k, v in control["protocolInput"].items() if k != "recordRead"}
                        and read_rest == {k: v for k, v in control["protocolInput"]["recordRead"].items()
                                          if k != "appliedTransfer"}):
                    with self.subTest(name=name):
                        # Figures without their committed change prove nothing
                        # either way. For the consumer, an authority about
                        # another block than the presented reference's
                        # bft-final inclusion contradicts nothing (DEM-7).
                        self.assertEqual("indeterminate" if differs == {"committedBalances"}
                                         or (refused == "fail" and differs == {"blockId"}) else refused,
                                         evaluate(vector)[0])
                        self.assertIn("success-requires-applied-transfer", vector["guards"])
                    witnessed |= differs
            self.assertEqual(APPLIED_TRANSFER, witnessed, prefix)
            # The phase network and the observed block ID are inputs: missing
            # or malformed ones bind nothing, on both paths.
            for change in ({"railNetwork": None}, {"railNetwork": {"networkId": proof["networkId"]}},
                           {"railNetwork": dict(control["protocolInput"]["railNetwork"], extra="x")},
                           {"railNetwork": {"networkId": "", "genesisHash": proof["genesisHash"]}},
                           {"inclusionObservation": {"blockNumber": generator.BLOCK}},
                           {"inclusionObservation": {"blockNumber": generator.BLOCK, "blockId": proof["blockId"].upper()}},
                           {"inclusionObservation": {"blockNumber": generator.BLOCK, "blockId": None}}):
                with self.subTest(control=control_name, change=str(change)[:60]):
                    case = json.loads(json.dumps(control))
                    for key, value in change.items():
                        if value is None:
                            del case["protocolInput"][key]
                        else:
                            case["protocolInput"][key] = value
                    self.assertEqual("indeterminate", evaluate(case)[0])
        # Resume re-reads under the same binding.
        resumed = json.loads(json.dumps(self.cases["resume-without-proof-confirmed"]))
        self.assertEqual("pass", evaluate(resumed)[0])
        resumed["protocolInput"]["recordRead"]["appliedTransfer"]["networkId"] = "demos:testnet"
        self.assertEqual("indeterminate", evaluate(resumed)[0])

    def test_every_dem1_refusal_holds_at_the_confirm_egress(self):
        # DEM-1 applies to each call that carries the signed transaction out
        # of the handler: a refusal at broadcast is the same refusal at the
        # demosdk confirm request that precedes it.
        # The validity-response refusals concern the broadcast payload only.
        payload = {"broadcast-carries-own-validity-response", "validity-response-binds-retained-transfer"}
        refusals = [
            vector for vector in self.data["vectors"]
            if vector["operation"] == "broadcast-gate" and vector["expected"] != "pass"
            and vector["protocolInput"]["request"] == "broadcast-retained"
            and vector["protocolInput"]["broadcastState"] == "confirm-returned"
            and not payload & set(vector["guards"])
        ]
        self.assertGreater(len(refusals), 40)
        for vector in refusals:
            with self.subTest(name=vector["name"]):
                confirm = json.loads(json.dumps(vector))
                confirm["protocolInput"].update(request="confirm-retained", broadcastState="never-broadcast",
                                                confirmResponse=None, validityResponse=None)
                self.assertEqual(evaluate(vector), evaluate(confirm))
                self.assertEqual(("pass", {"broadcastPermitted": True}),
                                 evaluate(confirm, {"retention-before-first-egress"}))

    def test_unknown_request_is_refused(self):
        control = self.cases["first-broadcast-after-durable-retention"]
        self.assertIn("any other value is refused", self.data["fixtureVocabulary"]["request"])
        for request in ("broadcast", "Broadcast-Retained", "confirm", None, ""):
            with self.subTest(request=request):
                case = json.loads(json.dumps(control))
                case["protocolInput"]["request"] = request
                self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(case))

    def test_plain_rpc_failure_proof_is_not_apr_reconciliation_evidence(self):
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("which the disposition's verifier checks itself, so a proof built on a plain read "
                      "authorizes no replacement through a later job", spec)
        self.assertIn("The handler's inclusion observation MAY be a plain read from a pinned node", spec)
        plain = self.cases["apr-evidence-plain-rpc-failure-proof"]
        self.assertEqual(("indeterminate", {"reconciliationEvidence": False}), evaluate(plain))
        self.assertEqual(("pass", {"reconciliationEvidence": True}),
                         evaluate(self.cases["apr-evidence-authenticated-failure-proof"]))
        # Missing or other authentication labels, and a corrupt authenticated proof, are not evidence.
        self.assertEqual("rpc-read", plain["protocolInput"]["retainedFailureProof"]["authentication"])
        for change in ({"authentication": None}, {"authentication": "FV5-BFT-FINAL"},
                       {"authentication": "bft-final"}):
            with self.subTest(change=change):
                case = json.loads(json.dumps(self.cases["apr-evidence-authenticated-failure-proof"]))
                case["protocolInput"]["retainedFailureProof"].update(change)
                self.assertEqual("indeterminate", evaluate(case)[0])
        unlabelled = json.loads(json.dumps(self.cases["apr-evidence-authenticated-failure-proof"]))
        del unlabelled["protocolInput"]["retainedFailureProof"]["authentication"]
        self.assertEqual("indeterminate", evaluate(unlabelled)[0])
        corrupt = json.loads(json.dumps(self.cases["apr-evidence-authenticated-failure-proof"]))
        corrupt["protocolInput"]["retainedFailureProof"]["record"]["content"]["nonce"] = str(generator.NONCE + 1)
        self.assertEqual("indeterminate", evaluate(corrupt)[0])

    def test_oversized_decimals_return_a_decision_in_every_path(self):
        # Untrusted decimals are compared by canonical spelling, never int().
        big = "9" * 4301
        self.assertEqual(big, _integer(big, "decode-amount", frozenset()))
        self.assertEqual(big, _lenient_spelling(" " + big + " "))
        self.assertEqual("1500000000", _lenient_spelling("1.5e9"))
        for name, expected in (("record-oversized-amount", "indeterminate"), ("record-oversized-nonce", "indeterminate"),
                               ("applied-transfer-oversized-debit", "indeterminate"),
                               ("broadcast-oversized-phase-amount", "fail"),
                               ("consumer-oversized-record-amount", "indeterminate"),
                               ("consumer-oversized-amount-bound", "pass")):
            with self.subTest(name=name):
                self.assertEqual(expected, evaluate(self.cases[name])[0])
        # The same values substituted into controls reach a decision too.
        control = json.loads(json.dumps(self.cases["first-broadcast-after-durable-retention"]))
        control["protocolInput"]["retainedTransfer"]["amountOs"] = big
        self.assertEqual("fail", evaluate(control)[0])
        consumer = json.loads(json.dumps(self.cases["consumer-confirmed-gate-passes"]))
        consumer["protocolInput"]["phase"]["amountOs"] = big
        self.assertEqual("indeterminate", evaluate(consumer)[0])

    def test_phase_os_amount_is_the_conversion_of_its_dem_amount(self):
        # DEM-1 converts phase.amount and DEM-7 reads phase.amountOs; both
        # describe one authenticated phase, so they must agree in every vector.
        for vector in self.data["vectors"]:
            phase = vector["protocolInput"].get("phase")
            if phase is None:
                continue
            with self.subTest(name=vector["name"]):
                self.assertEqual("DEM", phase["amount"]["currency"])
                whole, _, fraction = phase["amount"]["amount"].partition(".")
                # By spelling: the oversized phase amounts exceed int()'s digit limit.
                self.assertEqual(phase["amountOs"], (whole + fraction.ljust(9, "0")).lstrip("0") or "0")
        live = self.cases["consumer-node2-confirmed-refused"]["protocolInput"]["phase"]
        self.assertEqual({"amount": "9.5", "currency": "DEM"}, live["amount"])

    def test_a_demos_reference_has_no_legacy_spelling(self):
        """SB-1: only the frozen EVM, Solana and x402 arms have legacy
        spellings. No datum marks a Demos reference legacy, so a `0x` or
        upper-case Demos `txHash` is malformed (`error`) whoever calls it
        legacy, and an admission carries no `legacy` member."""
        base = self.cases["delivery-hash-admitted-for-another-job"]
        tx_hash = base["protocolInput"]["signedEvidence"]["txRef"]["txHash"]
        for spelling in ("0x" + tx_hash, tx_hash.upper(), "0x" + tx_hash.upper()):
            with self.subTest(spelling=spelling[:6]):
                case = json.loads(json.dumps(base))
                # The presented history and the index snapshot hold the same admission.
                for admission in (case["protocolInput"]["consumerAdmissions"][0],
                                  case["protocolInput"]["admissionIndex"]["admissions"][0]):
                    admission["txRef"]["txHash"] = spelling
                expected, want = evaluate(case)
                self.assertEqual("error", expected)
                self.assertFalse(want["deliveryAuthorized"])
                self.assertFalse(want["settlementAccounting"])
        for name in ("sb1-demos-current-prefixed", "sb1-demos-current-uppercase", "sb1-demos-prefixed-upper-case"):
            self.assertEqual("error", evaluate(self.cases[name])[0])
            self.assertNotIn("legacy", self.cases[name]["protocolInput"])
        self.assertEqual("error", evaluate(self.cases["sb2-demos-noncanonical-spelling"])[0])
        self.assertIn("A Demos `txHash` has no legacy spelling", SPEC.read_text(encoding="utf-8"))

    def test_a_flag_or_label_never_decides_fv5(self):
        """FV-5 is the signed execution result: in every operation, a read
        that says it is authenticated and a proof labelled `fv5-bft-final`
        decide exactly as the same read or proof without that word."""
        changed = 0
        for vector in self.data["vectors"]:
            value = vector["protocolInput"]
            read, proof = value.get("recordRead"), value.get("retainedFailureProof")
            if not isinstance(read, dict) and not isinstance(proof, dict):
                continue
            with self.subTest(name=vector["name"]):
                for claim in (True, False):
                    said = json.loads(json.dumps(vector))
                    if isinstance(read, dict) and "executionResult" not in read:
                        said["protocolInput"]["recordRead"]["authenticated"] = claim
                    if isinstance(proof, dict) and not isinstance(proof.get("authentication"), dict):
                        said["protocolInput"]["retainedFailureProof"]["authentication"] = (
                            "fv5-bft-final" if claim else "rpc-read")
                    self.assertEqual(evaluate(vector), evaluate(said))
                    changed += said != vector
        self.assertGreater(changed, 100)

    def test_the_oracle_verifies_fv5_as_the_settlement_finality_reference_does(self):
        """Every signed result in the corpus decides as the FV reference's own
        `_verify_demos_execution` does for the rail's network, the observed
        (or, in a proof, its own) block ID and the record's own reference. A
        carried `appliedTransfer` must also bind the record as the FV
        reference projects it: its transaction, block and parties, and the
        committed change of the record's amount (confirmed) or of nothing
        (failed)."""
        def applied_binds(result, record):
            applied = result.get("appliedTransfer")
            if applied is None:
                return True
            projection = _demos_native_send(record)
            moved = {"confirmed": (projection or {}).get("amountOs"), "failed": "0"}.get((projection or {}).get("status"))
            try:
                change = _demos_committed_change(applied["committedBalances"])
            except (KeyError, TypeError, ValueError):
                return False
            return (projection is not None and moved is not None and change == (moved, moved)
                    and (applied["payerDebitOs"], applied["payeeCreditOs"]) == change
                    and all(applied[k] == projection[k] for k in ("txHash", "blockNumber", "sender", "recipient")))

        checked = with_applied = 0
        for vector in self.data["vectors"]:
            value = vector["protocolInput"]
            proof = value.get("retainedFailureProof")
            read = value.get("recordRead") if isinstance(value.get("recordRead"), dict) else {}
            for result, record, block in (
                (read.get("executionResult"), read.get("record"),
                 (value.get("inclusionObservation") or {}).get("blockId")),
                (proof.get("authentication") if isinstance(proof, dict) else None,
                 proof.get("record") if isinstance(proof, dict) else None, _PROOF_BLOCK),
            ):
                if not isinstance(result, dict):
                    continue
                with self.subTest(name=vector["name"]):
                    network = value["railNetwork"]
                    observation = {**network, "executionResult": result, "inclusionBlock": {
                        "id": result.get("blockId") if block is _PROOF_BLOCK else block}}
                    reference = {"kind": "demos", "txHash": record.get("hash"), "blockNumber": record.get("blockNumber")}
                    decision, _reason, verified = _verify_demos_execution(
                        observation, reference, {"demosExecutionPolicy": value["fv5Policy"]})
                    expected = (decision == "pass" and _exact_json(verified["record"], record)
                                and applied_binds(result, record))
                    self.assertEqual(expected, fv5_result(result, record, value, block, frozenset()))
                    checked += 1
                    with_applied += "appliedTransfer" in result
        self.assertGreater(checked, 40)
        # The settlement-finality corpus's combined form, both ways.
        self.assertGreaterEqual(with_applied, 6)

    def test_fv5_accepts_the_settlement_finality_corpus_result_form(self):
        """FV-5's result in the settlement-finality corpus's combined form,
        with its signed `appliedTransfer`, authenticates the record the FV
        reference authenticates: delivery passes and a failed record is the
        DEM-4 failure and a DEM-7 refutation. The same result without the
        member decides alike. A result whose own signed `appliedTransfer`
        contradicts its record authenticates nothing."""
        for name, expected in (("delivery-fv-form-result", "pass"), ("included-failed-fv-form-result", "fail"),
                               ("consumer-failed-fv-form-result-fails", "fail")):
            with self.subTest(name=name):
                case = self.cases[name]
                read = case["protocolInput"]["recordRead"]
                result = read["executionResult"]
                self.assertIn("appliedTransfer", result)
                observation = {**case["protocolInput"]["railNetwork"], "executionResult": result,
                               "inclusionBlock": {"id": case["protocolInput"]["inclusionObservation"]["blockId"]}}
                reference = {"kind": "demos", "txHash": read["record"]["hash"],
                             "blockNumber": read["record"]["blockNumber"]}
                self.assertEqual("pass", _verify_demos_execution(
                    observation, reference, {"demosExecutionPolicy": case["protocolInput"]["fv5Policy"]})[0])
                self.assertEqual(expected, evaluate(case)[0])
                # The member is optional: the bare result decides the same.
                bare = json.loads(json.dumps(case))
                bare["protocolInput"]["recordRead"]["executionResult"] = generator.execution_result(read["record"])
                self.assertEqual(expected, evaluate(bare)[0])
        for name in ("delivery-fv-form-result-applied-another-amount", "delivery-fv-form-result-applied-not-committed-change",
                     "delivery-fv-form-result-applied-another-transaction", "included-failed-fv-form-result-shows-payment"):
            with self.subTest(name=name):
                case = self.cases[name]
                self.assertEqual("indeterminate", evaluate(case)[0])
                self.assertNotEqual("indeterminate", evaluate(case, {"fv5-result-applied-transfer-binds-record"})[0])

    def test_consumer_verdicts_agree_with_the_settlement_finality_reference(self):
        """The two corpora split on consumer inputs at f2148e4. Every pay-dem
        consumer vector's presented inclusion and FV-5 result go through the
        settlement-finality reference itself, in four directions: FV's fail
        or error on the inclusion is the consumer's verdict; FV-5 gives no
        fail for any result here (unauthenticated, or for another network,
        block or transaction), which the pay-dem oracle reads as
        authenticating nothing; FV-5's error is the consumer's error; and no
        delivery passes unless both FV halves pass. It does not compare
        pass and indeterminate classes beyond those directions."""
        checked = 0
        for vector in self.data["vectors"]:
            if vector["operation"] not in {"admit-evidence", "admit-for-delivery"}:
                continue
            value = vector["protocolInput"]
            read, reference = value["recordRead"], value["signedEvidence"]["txRef"]
            result, proof = read.get("executionResult"), read.get("inclusionProof")
            observed = value.get("inclusionObservation") or {}
            with self.subTest(name=vector["name"]):
                self.assertNotIn("fv", value.get("otherGates", {}))
                inclusion = "indeterminate"
                if isinstance(proof, dict):
                    inclusion = verify_transaction_inclusion(proof, value["finalityProfile"], reference,
                                                             value["finalityTrust"])[0]
                    checked += 1
                if inclusion in ("fail", "error"):
                    self.assertEqual(inclusion, vector["expected"])
                execution = None
                if result is not None:
                    execution = _verify_demos_execution(
                        {**value["railNetwork"], "inclusionBlock": {"id": observed.get("blockId")},
                         "executionResult": result},
                        reference, {"demosExecutionPolicy": value.get("fv5Policy")})[0]
                    self.assertNotEqual("fail", execution)
                    if execution == "error":
                        self.assertEqual("error", vector["expected"])
                if vector["operation"] == "admit-for-delivery" and vector["expected"] == "pass":
                    self.assertEqual(("pass", "pass"), (inclusion, execution))
        self.assertGreaterEqual(checked, 40)
        for name, expected in (("delivery-bft-final-certificate-forged", "fail"),
                               ("delivery-bft-final-transaction-absent", "fail"),
                               ("delivery-bft-final-block-off-authenticated-head", "fail"),
                               ("delivery-record-fv5-forged-result", "indeterminate")):
            with self.subTest(cold=name):
                self.assertEqual(expected, self.cases[name]["expected"])
                self.assertEqual(expected, evaluate(self.cases[name])[0])
                self.assertFalse(evaluate(self.cases[name])[1]["deliveryAuthorized"])
        # The FV corpus scores the same results the same way.
        fv = json.loads((ROOT / "conformance/vectors/security/settlement-finality-verification.json")
                        .read_text(encoding="utf-8"))
        verdicts = {vector["name"]: vector["expected"] for vector in fv["vectors"]}
        for suffix in ("status-tampered", "forged-confirmed", "duplicate-signer", "other-network", "other-genesis",
                       "other-block", "other-transaction", "quorum-missing", "unsigned"):
            with self.subTest(fv=suffix):
                self.assertEqual("indeterminate", verdicts["fv-bft-final-result-" + suffix])

    def test_signed_results_get_one_record_decision_across_corpora(self):
        """Every signed FV-5 result in this corpus (a read's, a retained
        proof's) goes through the settlement-finality reference's own entry
        points for the phase, `_verify_demos_execution` then
        `_verify_demos_record`, with no check of this test's own: the
        applied-transfer check both corpora share lives in them. A result the
        oracle reads as authenticating nothing is never FV's `fail` or `pass`;
        a handler's DEM-4 failure and APR evidence rest only on FV's `fail`;
        and a consumer's FV-5 refutation is FV's `fail`."""
        def fv_record(result, reference, value, read):
            phase = value.get("phase") or {}
            transfer = value.get("retainedTransfer") or {}
            job = phase.get("jobId", transfer.get("jobId"))
            index = phase.get("phaseIndex", transfer.get("phaseIndex"))
            payee = party_address(phase.get("payeeAddress", transfer.get("recipient")), frozenset())
            if payee is None:
                return "error"  # DEM-7: an unprojectable party address
            trusted = {
                "demosExecutionPolicy": value.get("fv5Policy"),
                "demosRecordProfile": DEMOS_RECORD_PROFILE,
                "demosPayerKeyClaims": {"payer": phase.get("payerKeyClaims") or [{
                    "claim": "key:" + str(party_address(phase.get("payerPayingKey", transfer.get("sender")),
                                                        frozenset())), "control": "presentation-signature"}]},
                "partyKeys": {"payee": base64.urlsafe_b64encode(bytes.fromhex(payee)).decode().rstrip("=")},
            }
            expected = {"jobId": job, "phaseIndex": index, "payer": "payer", "payee": "payee",
                        "amount": generator.dem_spelling(phase.get("amountOs", transfer.get("amountOs"))),
                        "currency": "DEM"}
            observation = {"networkId": result.get("networkId"), "genesisHash": result.get("genesisHash"),
                           "inclusionBlock": {"id": result.get("blockId")}, "executionResult": result}
            decision, _reason, verified = _verify_demos_execution(observation, reference, trusted)
            if decision != "pass":
                return decision
            # Without a carried applied transfer, the read's own applied-payment
            # authority (DEMOS-MAPPING §A.2) stands in for it, as on the pay-dem path.
            applied = verified.get("appliedTransfer")
            if applied is None and isinstance(read.get("appliedTransfer"), dict):
                applied = {k: v for k, v in read["appliedTransfer"].items() if k in FV5_APPLIED_TRANSFER}
            return _verify_demos_record(verified["record"], reference, expected, trusted, applied)[0]

        checked = {"consumer": 0, "handler": 0, "apr": 0}
        for vector in self.data["vectors"]:
            value = vector["protocolInput"]
            read = value.get("recordRead") if isinstance(value.get("recordRead"), dict) else {}
            proof = value.get("retainedFailureProof") if isinstance(value.get("retainedFailureProof"), dict) else {}
            result = read.get("executionResult") or proof.get("authentication")
            record = read.get("record") if "executionResult" in read else proof.get("record")
            if not (isinstance(result, dict) and isinstance(result.get("transactionRef"), dict)
                    and isinstance(record, dict) and _demos_native_send(record) is not None
                    and isinstance(value.get("fv5Policy"), dict)):
                continue
            consumer = vector["operation"] in {"admit-evidence", "admit-for-delivery"}
            reference = value["signedEvidence"]["txRef"] if consumer else result["transactionRef"]
            decision = fv_record(result, reference, value, read)
            with self.subTest(name=vector["name"]):
                if "appliedTransfer" in result and not fv5_applied_transfer(result["appliedTransfer"], record,
                                                                           frozenset()):
                    self.assertEqual("indeterminate", decision)
                if consumer:
                    checked["consumer"] += 1
                    authenticated = fv5_authenticated(read, value, frozenset(), reference)
                    if (authenticated and vector["expected"] == "fail"
                            and "consumer-authenticated-contradiction-fails" in vector["guards"]
                            and inclusion_verdict(read.get("inclusionProof"), reference, value, frozenset())
                            not in ("fail", "error")):
                        # Including a read that carries its appliedTransfer: the
                        # authority's own debit and credit are what FV scores.
                        self.assertEqual("fail", decision)
                    if vector["operation"] == "admit-for-delivery" and vector["expected"] == "pass":
                        self.assertEqual("pass", decision)
                elif vector["operation"] == "apr-reconciliation-evidence":
                    checked["apr"] += 1
                    if vector["expected"] == "pass":
                        self.assertEqual("fail", decision)
                elif record.get("status") == "failed":
                    checked["handler"] += 1
                    if vector["expected"] == "fail":
                        self.assertEqual("fail", decision)
                    if decision != "fail":
                        self.assertNotEqual("fail", vector["expected"])
        self.assertGreaterEqual(min(checked.values()), 5, checked)
        # The case that split the corpora: a signed failed record whose own
        # applied transfer shows the payment is no proven failure in either.
        shows_payment = self.cases["included-failed-fv-form-result-shows-payment"]
        self.assertEqual("indeterminate", shows_payment["expected"])
        fv = {vector["name"]: vector["expected"] for vector in json.loads(
            (ROOT / "conformance/vectors/security/settlement-finality-verification.json").read_text(encoding="utf-8")
        )["vectors"]}
        self.assertEqual("indeterminate", fv["fv-bft-final-included-execution-failed-shows-payment"])
        for suffix in ("wrong-hash", "wrong-block", "wrong-sender", "wrong-recipient", "zero-credit", "zero-debit"):
            self.assertEqual("indeterminate", fv["fv-bft-final-applied-transfer-" + suffix])
        self.assertEqual("indeterminate", self.cases["delivery-fv-form-result-applied-another-transaction"]["expected"])
        self.assertEqual("indeterminate", self.cases["delivery-fv-form-result-applied-another-amount"]["expected"])

    def test_equal_json_numbers_get_one_decision_across_corpora(self):
        """The node compares serialized edit lists, so `1` and `1.0` are one
        JSON number; the signed result's JCS bytes are the same too. Both the
        oracle and the settlement-finality reference compare numbers by value,
        and neither takes `true` or `"1"` for `1`."""
        vector = self.cases["delivery-fv-form-result"]
        self.assertEqual("pass", evaluate(vector)[0])
        for spelling, expected in ((1.0, "pass"), (True, "indeterminate"), ("1", "indeterminate")):
            with self.subTest(spelling=spelling):
                changed = json.loads(json.dumps(vector))
                read = changed["protocolInput"]["recordRead"]
                for record in (read["record"], read["executionResult"]["record"]):
                    record["content"]["gcr_edits"][3]["amount"] = spelling
                if expected == "pass":
                    self.assertEqual(canonicalize(vector["protocolInput"]["recordRead"]["executionResult"]),
                                     canonicalize(read["executionResult"]))
                    self.assertTrue(fv5_signed(read["executionResult"], changed["protocolInput"]["fv5Policy"]))
                self.assertEqual(expected == "pass", edits_match(read["record"]["content"]))
                self.assertEqual(expected == "pass", _demos_send_edits_match(read["record"]["content"]))
                self.assertEqual(expected, evaluate(changed)[0])

    def test_a_consumer_result_names_the_signed_reference(self):
        """Evidence for one transaction and a self-consistent signed result
        for another: the result is no result for this evidence, so it refutes
        nothing, in the oracle and in the settlement-finality reference."""
        vector = self.cases["consumer-wrong-hash-authenticated"]
        value = vector["protocolInput"]
        result, reference = value["recordRead"]["executionResult"], value["signedEvidence"]["txRef"]
        self.assertNotEqual(result["transactionRef"]["txHash"], reference["txHash"])
        self.assertEqual(("indeterminate", "indeterminate"), (vector["expected"], evaluate(vector)[0]))
        observation = {**value["railNetwork"], "inclusionBlock": {"id": result["blockId"]}, "executionResult": result}
        self.assertEqual("indeterminate", _verify_demos_execution(
            observation, reference, {"demosExecutionPolicy": value["fv5Policy"]})[0])
        # The wrong implementation authenticates the record against itself and refutes.
        self.assertEqual("fail", evaluate(vector, frozenset({"fv5-result-binds-signed-reference"}))[0])

    def test_a_proven_failure_needs_its_bft_final_inclusion(self):
        """DEM-4 and APR-6: a terminal failure, its reuse on resume and APR
        replacement evidence each need FV's bft-final verification of the
        transaction's inclusion in the block the verifying signed result
        names, checked by the settlement-finality reference itself. Without
        it, unfinalized, under a forged certificate, absent from the block,
        off the authenticated head or in another block, the phase stays
        unresolved and no replacement is authorized."""
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("That authentication is the FV `bft-final` verification of the transaction's inclusion "
                      "together with FV-5's authenticated execution result for the same record.", spec)
        self.assertNotIn("That authentication is FV-5's signed execution result itself", spec)
        terminal = {"included-failed": "classify", "node2-failed-record-authenticated": "classify",
                    "resume-reuses-failure-proof": "resume", "apr-evidence-authenticated-failure-proof": "apr"}
        for name, kind in terminal.items():
            with self.subTest(name=name):
                case = self.cases[name]
                value = case["protocolInput"]
                holder = value["retainedFailureProof"] if kind != "classify" else value["recordRead"]
                inclusion = holder["inclusionProof"]
                record = holder["record"]
                reference = {"kind": "demos", "txHash": record["hash"], "blockNumber": record["blockNumber"]}
                self.assertEqual(("pass", "transaction inclusion and finality verified"), verify_transaction_inclusion(
                    inclusion, value["finalityProfile"], reference, value["finalityTrust"]))
                self.assertEqual("bft-final", value["finalityProfile"]["kind"])
                self.assertIn("finalityCertificate", inclusion)
                # The same signed result without its inclusion half proves nothing.
                alone = json.loads(json.dumps(case))
                held = (alone["protocolInput"]["recordRead"] if kind == "classify"
                        else alone["protocolInput"]["retainedFailureProof"])
                del held["inclusionProof"]
                self.assertEqual(case["expected"], evaluate(case)[0])
                self.assertEqual("indeterminate", evaluate(alone)[0])
                self.assertEqual(case["expected"], evaluate(alone, {"failure-requires-bft-final-inclusion"})[0])
        refused = [vector for vector in self.data["vectors"]
                   if "-bft-final-" in vector["name"] and "failure-requires-bft-final-inclusion" in vector["guards"]]
        self.assertEqual({"classify-execution": 7, "resume-phase": 6, "apr-reconciliation-evidence": 6},
                         {op: sum(v["operation"] == op for v in refused) for op in
                          ("classify-execution", "resume-phase", "apr-reconciliation-evidence")})
        for vector in refused:
            with self.subTest(name=vector["name"]):
                expected, want = evaluate(vector)
                self.assertEqual("indeterminate", expected)
                self.assertFalse(want.get("replacementPermitted", False))
                self.assertFalse(want.get("reconciliationEvidence", False))
                self.assertFalse(want.get("terminalFailureProofRetained", False))
                # The signed result verifies in each: only the inclusion half refuses.
                value = vector["protocolInput"]
                holder = value.get("retainedFailureProof") or value["recordRead"]
                result = holder.get("authentication") or holder.get("executionResult")
                block = (value.get("inclusionObservation") or {}).get("blockId", _PROOF_BLOCK)
                self.assertTrue(fv5_result(result, holder["record"], value,
                                           _PROOF_BLOCK if "retainedFailureProof" in value and value["retainedFailureProof"] else block,
                                           frozenset()))

    def test_every_final_verdict_needs_its_bft_final_inclusion(self):
        """PC-7 and DEM-3/DEM-7: payer success, the consumer's FV-5 refutation
        and delivery each need FV's bft-final verification of the
        transaction's inclusion, as DEM-4 does. A bound confirmed record, or a
        signed failure, in a block that is not shown final decides nothing."""
        final = {"included-confirmed": "success-requires-bft-final-inclusion",
                 "resume-without-proof-confirmed": "success-requires-bft-final-inclusion",
                 "consumer-failed-fails": "consumer-refutation-requires-bft-final-inclusion",
                 "consumer-wrong-payee-authenticated": "consumer-refutation-requires-bft-final-inclusion",
                 "consumer-four-edits-uncommitted-payment": "consumer-contradiction-requires-bft-final-inclusion",
                 "consumer-applied-transfer-wrong-recipient": "consumer-contradiction-requires-bft-final-inclusion",
                 "delivery-after-all-gates": "delivery-requires-bft-final-inclusion"}
        for name, guard in final.items():
            with self.subTest(name=name):
                case = self.cases[name]
                value = case["protocolInput"]
                self.assertEqual("bft-final", value["finalityProfile"]["kind"])
                self.assertIn("finalityCertificate", value["recordRead"]["inclusionProof"])
                self.assertIn(case["expected"], {"pass", "fail"})
                self.assertEqual(case["expected"], evaluate(case)[0])
                for strip in ("inclusionProof", "certificate", "trust"):
                    stripped = json.loads(json.dumps(case))
                    held = stripped["protocolInput"]
                    if strip == "inclusionProof":
                        del held["recordRead"]["inclusionProof"]
                    elif strip == "certificate":
                        del held["recordRead"]["inclusionProof"]["finalityCertificate"]
                    else:
                        held["finalityProfile"], held["finalityTrust"] = {}, {}
                    self.assertEqual("indeterminate", evaluate(stripped)[0], strip)
                    self.assertEqual(case["expected"], evaluate(stripped, {guard})[0], strip)
        refused = [vector for vector in self.data["vectors"]
                   if {"success-requires-bft-final-inclusion", "consumer-refutation-requires-bft-final-inclusion",
                       "consumer-contradiction-requires-bft-final-inclusion",
                       "delivery-requires-bft-final-inclusion"} & set(vector["guards"])]
        self.assertEqual({"classify-execution": 7, "resume-phase": 1, "admit-evidence": 19, "admit-for-delivery": 4},
                         {op: sum(v["operation"] == op for v in refused) for op in
                          ("classify-execution", "resume-phase", "admit-evidence", "admit-for-delivery")})
        # The inclusions FV itself scores fail (a forged certificate, a
        # transaction proven absent, a block off the authenticated head) are
        # the consumer's fail, as in the settlement-finality corpus, and
        # authorize nothing; the payer's DEM-3/DEM-4 stay unresolved on them.
        forged = [vector for vector in self.data["vectors"]
                  if "consumer-takes-fv-inclusion-verdict" in vector["guards"]]
        # Six forged-inclusion variants, and two that pair the forged
        # certificate with a bundle that controls nothing or is malformed: FV-10
        # is decided before the claims (DEM-7).
        self.assertEqual({"admit-evidence": 8, "admit-for-delivery": 3},
                         {op: sum(v["operation"] == op for v in forged) for op in ("admit-evidence", "admit-for-delivery")})
        for vector in forged:
            with self.subTest(forged=vector["name"]):
                expected, want = evaluate(vector)
                self.assertEqual("fail", expected)
                self.assertFalse(want.get("deliveryAuthorized"))
                self.assertFalse(want.get("settlementAccounting", False))
        for vector in self.data["vectors"]:
            if vector["operation"] in {"classify-execution", "resume-phase"} and any(
                    vector["name"].endswith(suffix) for suffix in generator.FV_INCLUSION_FAILS):
                with self.subTest(handler=vector["name"]):
                    self.assertEqual("indeterminate", evaluate(vector)[0])
        for vector in refused:
            with self.subTest(name=vector["name"]):
                expected, want = evaluate(vector)
                self.assertEqual("indeterminate", expected)
                self.assertFalse(want.get("ok"))
                self.assertFalse(want.get("deliveryAuthorized"))
                self.assertFalse(want.get("settlementAccounting", False))
                self.assertFalse(want.get("replacementPermitted", False))

    # Each operation's final verdicts about the Demos payment: DEM-3 success,
    # a DEM-4 failure (and its reuse), APR evidence, DEM-7's `fail` and
    # delivery. A DEM-7 `pass` alone is one gate, not a final verdict.
    FINAL_VERDICTS = {"classify-execution": {"pass", "fail"}, "resume-phase": {"pass", "fail"},
                      "apr-reconciliation-evidence": {"pass"}, "admit-evidence": {"fail"},
                      "admit-for-delivery": {"pass", "fail"}}

    def test_no_final_verdict_survives_without_its_bft_final_inclusion(self):
        """The Finality rule over every vector, whichever branch decides it:
        without the bft-final inclusion proofs it carries, or without their
        finality certificates, no final verdict remains."""
        def strip(value, member):
            if isinstance(value, dict):
                value.pop(member, None)
                for item in value.values():
                    strip(item, member)
            elif isinstance(value, list):
                for item in value:
                    strip(item, member)

        checked = 0
        for vector in self.data["vectors"]:
            if vector["expected"] not in self.FINAL_VERDICTS.get(vector["operation"], ()):
                continue
            checked += 1
            for member in ("inclusionProof", "finalityCertificate"):
                with self.subTest(name=vector["name"], strip=member):
                    stripped = json.loads(json.dumps(vector))
                    strip(stripped["protocolInput"], member)
                    want = "indeterminate"
                    phase = stripped["protocolInput"].get("phase") or {}
                    if "payerKeyClaims" in phase and payer_claims(phase, frozenset()) is None:
                        want = "error"  # a malformed bundle claim is decided once FV-10 decides nothing
                    if member == "finalityCertificate" and "consumer-takes-fv-inclusion-verdict" in vector["guards"]:
                        # The verdict is FV's own on the presented proof, which
                        # can still show the transaction absent or off the
                        # authenticated head without a certificate (FV-10).
                        held = stripped["protocolInput"]
                        fv = inclusion_verdict(held["recordRead"]["inclusionProof"], held["signedEvidence"]["txRef"],
                                               held, frozenset())
                        want = fv if fv in ("fail", "error") else want
                    self.assertEqual(want, evaluate(stripped)[0])
        self.assertGreaterEqual(checked, 30)

    def test_a_plain_observation_never_decides_a_final_verdict(self):
        """A stale or forked pinned node names another block ID at the
        height: the plain observation never creates a final verdict and
        never turns a payment into `fail` (DEM-2: the pin does not
        authenticate that read)."""
        checked = 0
        for vector in self.data["vectors"]:
            observation = vector["protocolInput"].get("inclusionObservation")
            if vector["operation"] not in self.FINAL_VERDICTS or not isinstance(observation, dict):
                continue
            checked += 1
            with self.subTest(name=vector["name"]):
                stale = json.loads(json.dumps(vector))
                stale["protocolInput"]["inclusionObservation"]["blockId"] = "ab" * 32
                self.assertIn(evaluate(stale)[0], {vector["expected"], "indeterminate"})
        self.assertGreaterEqual(checked, 200)
        # The honest authority of a final payment against a stale observation.
        for name in ("consumer-stale-observed-block-refutes-nothing", "delivery-stale-observed-block-refutes-nothing"):
            with self.subTest(name=name):
                case = self.cases[name]
                self.assertEqual("indeterminate", evaluate(case)[0])
                self.assertEqual("fail", evaluate(case, {"consumer-contradiction-requires-bft-final-inclusion"})[0])

    def test_only_an_authenticated_failed_record_refutes_evidence(self):
        self.assertEqual("fail", evaluate(self.cases["consumer-failed-fails"])[0])
        self.assertIn("executionResult", self.cases["consumer-failed-fails"]["protocolInput"]["recordRead"])
        unauthenticated = self.cases["consumer-failed-unauthenticated"]
        self.assertEqual("indeterminate", evaluate(unauthenticated)[0])
        self.assertNotIn("executionResult", unauthenticated["protocolInput"]["recordRead"])
        # The earlier draft's flag is a plain read whoever sets it.
        flagged = self.cases["consumer-failed-fv5-flag-only"]
        self.assertIs(True, flagged["protocolInput"]["recordRead"]["authenticated"])
        self.assertEqual("indeterminate", evaluate(flagged)[0])

    def test_authentic_other_sender_must_match_retained_payer(self):
        case = self.cases["broadcast-signed-sender-differs"]
        value = case["protocolInput"]
        self.assertTrue(authentic(value["signedTransaction"]))
        self.assertNotEqual(value["retainedTransfer"]["sender"],
                            value["signedTransaction"]["content"]["from"].removeprefix("0x"))
        self.assertEqual("fail", evaluate(case)[0])
        self.assertEqual("pass", evaluate(case, {"signed-transfer-matches-retention"})[0])

    def test_sdk_json_stringify_numbers_preserve_signed_content(self):
        # Literal outputs of JavaScript JSON.stringify; preserve non-NFC strings and member order.
        content = {"z": 1e-7, "a": 1.0, "tiny": 1e-6, "negativeZero": -0.0,
                   "text": "e\u0301", "10": 10, "2": 2}
        serialized = '{"2":2,"10":10,"z":1e-7,"a":1,"tiny":0.000001,"negativeZero":0,"text":"e\u0301"}'
        self.assertEqual(serialized, stringify(content))
        # 4294967294 is the largest array index; 4294967295 and longer decimal names keep insertion order.
        long_name = "9" * 4301
        for value, spelling in (
            ({"n": None, "t": True, "f": False}, '{"n":null,"t":true,"f":false}'),
            # 4294967295 follows "a" in insertion order, so treating it as an index would move it.
            ({"a": 2, "4294967295": 1, "4294967294": 3, "0": 4}, '{"0":4,"4294967294":3,"a":2,"4294967295":1}'),
            ({long_name: 1, "1": 2}, '{"1":2,"' + long_name + '":1}'),
        ):
            with self.subTest(value=spelling[:40]):
                self.assertEqual(spelling, stringify(value))
        # A member name that is not a string is not JSON.
        for value in ({1: "x"}, {"a": 1, 2: "y"}, (1, 2)):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    stringify(value)
        for number, spelling in ((1e-7, "1e-7"), (1.0, "1"), (1e-6, "0.000001"), (-0.0, "0")):
            with self.subTest(number=number):
                body = generator.send_content(nonce=generator.NONCE, amount=generator.AMOUNT_OS, extra=number)
                # Independent expected SDK bytes, before signing the deterministic fixture hash.
                expected = json.dumps({k: v for k, v in body.items() if k != "extra"}, separators=(",", ":"))[:-1] + ',"extra":' + spelling + '}'
                tx_hash = hashlib.sha256(expected.encode()).hexdigest()
                transaction = {"content": body, "hash": tx_hash,
                               "signature": {"type": "ed25519", "data": "0x" + generator.PAYER_SIGNER.sign(tx_hash.encode()).hex()}}
                self.assertTrue(authentic(transaction))
                self.assertEqual(tx_hash, generator.content_hash(body))

    def test_inclusion_only_implementation_is_rejected(self):
        wrong = {
            vector["name"]
            for vector in self.data["vectors"]
            if evaluate(vector, {"success-requires-record"}) != evaluate(vector)
        }
        self.assertIn("included-failed", wrong)
        self.assertIn("node2-included-failed-record", wrong)
        self.assertIn("included-record-not-found", wrong)
        consumer = {
            vector["name"]
            for vector in self.data["vectors"]
            if evaluate(vector, {"consumer-requires-confirmed-record"}) != evaluate(vector)
        }
        self.assertIn("consumer-included-only-refused", consumer)
        self.assertIn("consumer-failed-fails", consumer)
        self.assertIn("delivery-dem7-pending", consumer)

    def test_handler_never_permits_a_second_or_replacement_broadcast(self):
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                want = vector["want"]
                if vector["operation"] in {"classify-execution", "resume-phase"}:
                    self.assertFalse(want["broadcastPermitted"])
                    self.assertFalse(want["replacementPermitted"])
                if vector["operation"] == "broadcast-gate" and want["broadcastPermitted"]:
                    # Nothing has left the handler before this confirm, or this
                    # broadcast completes the uninterrupted submission whose
                    # confirm just returned. A demosdk broadcast needs a
                    # validity response, so it is never the first egress.
                    state = vector["protocolInput"]["broadcastState"]
                    request = vector["protocolInput"]["request"]
                    self.assertIs(False, vector["protocolInput"]["restartedSinceRetention"])
                    self.assertIn((state, request), {
                        ("never-broadcast", "confirm-retained"),
                        ("confirm-returned", "broadcast-retained"),
                    })
        # DEM-6 "never repeat a call": a confirm after the first egress is
        # refused in every later state, each by its own corpus vector.
        repeated = {
            (vector["protocolInput"]["broadcastState"], vector["name"])
            for vector in self.data["vectors"]
            if vector["operation"] == "broadcast-gate" and vector["protocolInput"]["request"] == "confirm-retained"
            and vector["protocolInput"]["broadcastState"] != "never-broadcast"
        }
        self.assertEqual({("confirm-sent-interrupted", "confirm-after-interrupted-confirm-refused"),
                          ("maybe-broadcast", "confirm-after-maybe-broadcast-refused"),
                          ("confirm-returned", "confirm-after-confirm-returned-refused")}, repeated)
        for _, name in repeated:
            with self.subTest(repeat=name):
                self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(self.cases[name]))
                self.assertEqual(("pass", {"broadcastPermitted": True}), evaluate(self.cases[name], {"no-rebroadcast"}))

    def test_proven_failure_is_durable_and_omits_settlement_finality(self):
        for vector in self.data["vectors"]:
            if vector["operation"] in {"classify-execution", "resume-phase"} and (
                vector["expected"] == "fail"
            ):
                with self.subTest(name=vector["name"]):
                    want = vector["want"]
                    self.assertEqual("permanent", want["errorClass"])
                    self.assertTrue(want["terminalFailureProofRetained"])
                    self.assertEqual("failure-without-settlement-finality", want["evidence"])

    def test_only_an_fv5_authenticated_failed_record_is_a_terminal_failure(self):
        """DEM-4 is terminal only for a bound failed record authenticated under
        FV-5 at its bft-final inclusion. A plain RPC read of one, which the
        pin does not authenticate, is DEM-5: a stale or dishonest pinned node
        can serve failed for a transfer whose committed payment applied."""
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("For a bound record whose status is exactly `failed` and that is authenticated under FV-5 "
                      "at its `bft-final` inclusion, the handler MUST return", spec)
        self.assertIn("The handler MUST NOT return `errorClass: \"permanent\"` for it; it stays unresolved under DEM-5.", spec)
        self.assertIn("a bound `failed` record from a plain RPC read, and every outcome of the handler's own "
                      "check or call once the signed transaction may have left", spec)
        self.assertIn("- bound `failed` record from a plain RPC read → `substrate`", spec)
        self.assertIn("FV-5's signed result alone does not show both: it can verify for a block that is not final.", spec)
        # The FV reference no longer returns an execution result's fail before its path checks.
        self.assertNotIn("FV-5 can return `fail` for the execution result before the inclusion checks", spec)
        terminal = 0
        for vector in self.data["vectors"]:
            if vector["operation"] not in {"classify-execution", "resume-phase"} or vector["expected"] != "fail":
                continue
            with self.subTest(name=vector["name"]):
                value = vector["protocolInput"]
                proof = value.get("retainedFailureProof")
                plain = json.loads(json.dumps(vector))
                if proof is not None:
                    self.assertTrue(authenticated_proof(proof, value, frozenset()))
                    # The earlier draft's label in place of the signed result.
                    plain["protocolInput"]["retainedFailureProof"]["authentication"] = "fv5-bft-final"
                else:
                    self.assertTrue(fv5_authenticated(value["recordRead"], value, frozenset()))
                    del plain["protocolInput"]["recordRead"]["executionResult"]
                    plain["protocolInput"]["recordRead"]["authenticated"] = True
                # The same observation as a plain read never ends the phase.
                expected, want = evaluate(plain)
                self.assertEqual("indeterminate", expected)
                self.assertEqual("substrate", want["errorClass"])
                self.assertFalse(want["terminalFailureProofRetained"])
                terminal += 1
        self.assertGreaterEqual(terminal, 3)
        # The forged failure: the record says failed while the authenticated
        # committed balances show the phase payment applied.
        forged = self.cases["failed-plain-read-over-applied-payment"]
        read = forged["protocolInput"]["recordRead"]
        self.assertEqual("failed", read["record"]["status"])
        self.assertEqual((generator.AMOUNT_OS, generator.AMOUNT_OS), committed_change(read["appliedTransfer"]))
        self.assertEqual("indeterminate", evaluate(forged)[0])
        self.assertEqual("fail", evaluate(forged, {"failure-requires-authentication"})[0])
        # A phase that an earlier draft ended on that plain-read failure:
        # the proof is never reused, and the later re-read that finds the
        # executed transfer is post-terminal, so it never reopens the phase.
        later = self.cases["resume-plain-read-failure-then-authenticated-confirmed"]
        self.assertEqual("rpc-read", later["protocolInput"]["retainedFailureProof"]["authentication"])
        self.assertEqual("indeterminate", evaluate(later)[0])
        self.assertEqual("fail", evaluate(later, {"resume-requires-authenticated-proof"})[0])
        self.assertEqual("indeterminate", evaluate(self.cases["resume-plain-read-failure-proof-not-reused"])[0])

    def test_a_resume_after_a_terminal_failure_never_succeeds(self):
        """DEM-4/DEM-6: a retained failure proof means the phase ended. A
        resume reuses the proof only while it verifies; otherwise it re-reads,
        and that post-terminal read can prove the failure again but never
        returns pass, whatever the record and authority show. The handler
        that re-derives the ended phase from the re-read alone reopens it."""
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("That re-read is post-terminal (DEM-6): it returns `errorClass: \"permanent\"` only when it "
                      "proves the failure again, and otherwise `ok: false` with `errorClass: \"substrate\"`; it MUST NOT "
                      "return `ok: true`, whatever the record and its applied-payment authority show.", spec)
        ended = [vector for vector in self.data["vectors"]
                 if vector["operation"] == "resume-phase" and vector["protocolInput"]["retainedFailureProof"] is not None]
        self.assertGreaterEqual(len(ended), 15)
        for vector in ended:
            with self.subTest(name=vector["name"]):
                self.assertNotEqual("pass", vector["expected"])
                self.assertNotEqual("pass", evaluate(vector)[0])
        for name in ("resume-plain-read-failure-then-authenticated-confirmed",
                     "resume-failure-proof-no-longer-verifies-then-confirmed"):
            with self.subTest(name=name):
                vector = self.cases[name]
                self.assertEqual("confirmed", vector["protocolInput"]["recordRead"]["record"]["status"])
                self.assertIn("terminal-never-reopens", vector["guards"])
                self.assertEqual("pass", evaluate(vector, {"terminal-never-reopens"})[0])
        # Without a retained proof nothing has ended, and the re-read settles.
        self.assertEqual("pass", evaluate(self.cases["resume-without-proof-confirmed"])[0])

    def test_restart_makes_a_retained_transfer_maybe_broadcast(self):
        """DEM-6: a handler that journals late, or a journal that lost its
        last write, shows no entry for a call that was made, so after a
        (re)start a retained transfer is maybe-broadcast whatever state the
        handler recorded, and a missing entry never shows that nothing left.
        The liveness cost is stated beside the rule."""
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("A transfer the handler finds retained when it starts or restarts MUST therefore be treated "
                      "as possibly broadcast, whatever progress its journal records, and the handler MUST NOT "
                      "conclude from a missing entry that nothing left.", spec)
        self.assertNotIn("A crash can fall between a call that carried the signed transaction and the journal entry", spec)
        self.assertIn("A start or restart between the retention and the first `confirm` leaves the handler with a "
                      "retained transfer it must treat as possibly broadcast", spec)
        self.assertIn("the phase stays `substrate` and ends `failed-substrate` at ST-7 expiry", spec)
        for name in ("confirm-after-restart-refused", "replacement-after-restart-refused",
                     "broadcast-after-restart-from-confirm-returned-refused", "broadcast-gate-restart-unstated"):
            with self.subTest(name=name):
                self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(self.cases[name]))
                self.assertEqual(("pass", {"broadcastPermitted": True}),
                                 evaluate(self.cases[name], {"restart-is-maybe-broadcast"}))
        permitted = [vector for vector in self.data["vectors"]
                     if vector["operation"] == "broadcast-gate" and vector["expected"] == "pass"]
        self.assertTrue(permitted)
        for vector in permitted:
            # The same permitted egress after a restart, or with the restart
            # left unstated or misspelled, is refused (fail closed).
            for restarted in (True, None, "false", 0, _ABSENT):
                with self.subTest(name=vector["name"], restarted=restarted):
                    case = json.loads(json.dumps(vector))
                    if restarted is _ABSENT:
                        del case["protocolInput"]["restartedSinceRetention"]
                    else:
                        case["protocolInput"]["restartedSinceRetention"] = restarted
                    self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(case))

    def test_own_call_outcomes_after_the_first_egress_are_substrate(self):
        """PC-4 for pay-dem: once a confirm or broadcast may have carried the
        signed bytes, a refusal (insufficient balance included), a transport
        error, a timeout, an unrecognized reply and an accepted broadcast are
        each DEM-5 substrate with the retained hash kept and no further call.
        Only a refusal found before any egress, on a journal that has not
        restarted, is permanent."""
        spec = SPEC.read_text(encoding="utf-8")
        pc4 = spec[spec.index("**(PC-4)**"):spec.index("**(PC-5)**")]
        self.assertIn("for `pay-dem`, only a refusal found before the signed transfer's first egress (including a "
                      "paying key or payee address that does not project, found before signing) or a DEM-4 proven "
                      "failure, nothing else (§9.5.9)", pc4)
        self.assertIn("for `pay-dem`, never: every failure after the first egress, RPC failure and mempool "
                      "congestion included, is `substrate` (§9.5.9 DEM-5)", pc4)
        egress = [vector for vector in self.data["vectors"] if vector["operation"] == "classify-egress-outcome"]
        self.assertLessEqual({
            "egress-insufficient-balance-before-first-egress",
            "egress-confirm-refused-insufficient-balance",
            "egress-confirm-transport-error",
            "egress-confirm-timeout",
            "egress-broadcast-transport-error",
            "egress-broadcast-refused-by-dem1-after-valid-confirm",
        }, {vector["name"] for vector in egress})
        permanent = 0
        for vector in egress:
            value, want = vector["protocolInput"], vector["want"]
            with self.subTest(name=vector["name"]):
                cause = f'{value["call"]}:{value["outcome"]}'
                self.assertEqual(cause, want["cause"])
                before = (value["call"] == "pre-egress-check" and value["broadcastState"] == "never-broadcast"
                          and value["restartedSinceRetention"] is False)
                if before and value["outcome"] == "insufficient-balance":
                    self.assertEqual(("fail", dict(NOT_SENT_WANT, cause=cause)), evaluate(vector))
                    permanent += 1
                else:
                    self.assertEqual(("indeterminate", dict(HANDLER_WANT["indeterminate"], cause=cause)),
                                     evaluate(vector))
        self.assertEqual(1, permanent)
        # The wrong implementations follow the bare PC-4 rows after the bytes
        # left; each is caught by a vector.
        for guard, wrong in (("post-egress-refusal-is-unresolved", "permanent"),
                             ("call-error-is-unresolved", "transient")):
            with self.subTest(guard=guard):
                self.assertTrue([vector["name"] for vector in egress
                                 if evaluate(vector, {guard})[1]["errorClass"] == wrong])
        self.assertIs(True, evaluate(self.cases["egress-broadcast-accepted-is-not-success"],
                                     {"success-requires-record"})[1]["ok"])
        # The control refused before any egress becomes substrate as soon as
        # anything says the bytes may have left, or says nothing (fail closed).
        control = self.cases["egress-insufficient-balance-before-first-egress"]
        for member, value in (
            ("restartedSinceRetention", True), ("restartedSinceRetention", None),
            ("restartedSinceRetention", "false"), ("restartedSinceRetention", 0),
            ("restartedSinceRetention", _ABSENT), ("broadcastState", "confirm-sent-interrupted"),
            ("broadcastState", "confirm-returned"), ("broadcastState", "maybe-broadcast"),
            ("broadcastState", "unrecognized"), ("call", "confirm"), ("call", "broadcast"),
            ("call", "sr3-proxy-submission"),
        ):
            with self.subTest(member=member, value=value):
                case = json.loads(json.dumps(control))
                if value is _ABSENT:
                    del case["protocolInput"][member]
                else:
                    case["protocolInput"][member] = value
                expected, want = evaluate(case)
                self.assertEqual("indeterminate", expected)
                self.assertEqual("substrate", want["errorClass"])
                self.assertFalse(want["broadcastPermitted"])

    def test_payee_history_is_the_snapshot_of_its_durable_admission_index(self):
        """DEM-7: the history the payee presents before delivery is the
        snapshot of its durable admission index. A presented list that omits
        an indexed admission, as a restart with process-local history would,
        never lets a reused hash deliver."""
        spec = SPEC.read_text(encoding="utf-8")
        dem7 = spec[spec.index("**(DEM-7) Consumer admission.**"):spec.index("**Finality.** Demos")]
        self.assertIn("The payee's admissions are its *admission index*", dem7)
        self.assertIn("MUST durably add each admitted evidence", dem7)
        self.assertIn("with a write conditional on that snapshot's revision", dem7)
        self.assertIn("is `error` and authorizes no delivery", dem7)
        deliveries = [vector for vector in self.data["vectors"] if vector["operation"] == "admit-for-delivery"]
        for vector in deliveries:
            with self.subTest(name=vector["name"]):
                self.assertIn("admissionIndex", vector["protocolInput"])
                if vector["want"]["deliveryAuthorized"]:
                    value = vector["protocolInput"]
                    self.assertEqual(history(value["consumerAdmissions"]),
                                     history(value["admissionIndex"]["admissions"]))
        # The reviewer's probe: the earlier admission dropped from the
        # presented history delivered against the reused hash before this rule.
        base = self.cases["delivery-hash-admitted-for-another-job"]
        dropped = json.loads(json.dumps(base))
        dropped["protocolInput"]["consumerAdmissions"] = []
        expected, want = evaluate(dropped)
        self.assertEqual("error", expected)
        self.assertFalse(want["deliveryAuthorized"])
        self.assertFalse(want["settlementAccounting"])
        self.assertEqual("pass", evaluate(dropped, {"delivery-history-is-admission-index"})[0])
        self.assertEqual(dropped["protocolInput"],
                         self.cases["delivery-history-omits-indexed-admission"]["protocolInput"])
        # The snapshot is a multiset: order does not matter, a duplicate does.
        reordered = json.loads(json.dumps(base))
        extra = dict(reordered["protocolInput"]["consumerAdmissions"][0], phaseIndex=generator.PHASE_INDEX + 1)
        reordered["protocolInput"]["consumerAdmissions"].append(extra)
        reordered["protocolInput"]["admissionIndex"]["admissions"].insert(0, dict(extra))
        self.assertEqual("indeterminate", evaluate(reordered)[0])
        reordered["protocolInput"]["consumerAdmissions"].append(dict(extra))
        self.assertEqual("error", evaluate(reordered)[0])
        # No snapshot at all, in any spelling, is error.
        control = self.cases["delivery-after-all-gates"]
        for index in (_ABSENT, None, [], {"revision": 0}, {"revision": -1, "admissions": []},
                      {"revision": True, "admissions": []}, {"revision": 0, "admissions": [None]},
                      {"revision": 0, "admissions": [], "extra": 1}):
            with self.subTest(index=index):
                case = json.loads(json.dumps(control))
                if index is _ABSENT:
                    del case["protocolInput"]["admissionIndex"]
                else:
                    case["protocolInput"]["admissionIndex"] = index
                self.assertEqual("error", evaluate(case)[0])
                self.assertFalse(evaluate(case)[1]["deliveryAuthorized"])

    def test_signed_nonce_above_the_safe_integer_bound_is_refused(self):
        """DEMOS-MAPPING §A.2 bounds the signed nonce at 2^53 - 1. JCS cannot
        carry a larger integer in the corpus (nor can demosdk's serializer
        hash one), so this raises the nonce of a bound-valid transfer in memory."""
        at_bound = generator.consistent(generator.send_content(nonce=SAFE_MAX, amount=generator.AMOUNT_OS),
                                        nonce=SAFE_MAX)
        control = generator.gate("nonce-at-bound", "pass", "DEM-1", ["first-broadcast-allowed"], "",
                                 signed_transaction=at_bound["signed_transaction"], transfer=at_bound["transfer"])
        self.assertEqual(("pass", {"broadcastPermitted": True}), evaluate(control))
        self.assertIsNotNone(decode(at_bound["signed_transaction"], frozenset(), executed=False))
        for nonce in (SAFE_MAX + 1, 2**64):
            with self.subTest(nonce=nonce):
                case = json.loads(json.dumps(control))
                case["protocolInput"]["signedTransaction"]["content"]["nonce"] = nonce
                self.assertIsNone(decode(case["protocolInput"]["signedTransaction"], frozenset(), executed=False))
                self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(case))

    def test_every_authority_is_the_change_of_its_committed_balances(self):
        """Every passing record carries the four edits of its send, and every
        fixture authority (except the one deliberately inconsistent pair) is
        the change of the committed balances it authenticates: a debit and
        credit of the OS amount on every passing vector, with balances that
        actually moved. The record's amount and edits are never consulted."""
        inconsistent = {"confirmed-four-edits-authority-not-committed-change",
                        "consumer-four-edits-authority-not-committed-change"}
        checked = 0
        for vector in self.data["vectors"]:
            read = vector["protocolInput"].get("recordRead")
            if not (isinstance(read, dict) and isinstance(read.get("record"), dict)):
                continue
            with self.subTest(name=vector["name"]):
                proof = read.get("appliedTransfer")
                if vector["expected"] == "pass":
                    # A record FV-5 authenticates compares its edits by member,
                    # as the settlement-finality reference does.
                    self.assertTrue(edits_match(read["record"]["content"])
                                    or _demos_send_edits_match(read["record"]["content"]))
                    amount = (vector["protocolInput"].get("phase") or vector["protocolInput"]["retainedTransfer"])["amountOs"]
                    self.assertEqual((amount, amount), committed_change(proof))
                    balances = proof["committedBalances"]
                    self.assertNotEqual(balances["payerBeforeOs"], balances["payerAfterOs"])
                    self.assertNotEqual(balances["payeeBeforeOs"], balances["payeeAfterOs"])
                if proof is not None and vector["name"] not in inconsistent:
                    self.assertEqual(committed_change(proof), (proof["payerDebitOs"], proof["payeeCreditOs"]))
                    checked += 1
        self.assertGreater(checked, 80)
        for name in inconsistent:
            proof = self.cases[name]["protocolInput"]["recordRead"]["appliedTransfer"]
            self.assertEqual(("0", "0"), committed_change(proof))
            self.assertNotEqual(("0", "0"), (proof["payerDebitOs"], proof["payeeCreditOs"]))

    def test_fixture_authority_never_follows_the_record(self):
        """The generator's authority reports the scenario's committed state:
        rewriting the record's edits, amount or status leaves it unchanged."""
        base = generator.record("confirmed")
        want = generator.found(base)["appliedTransfer"]
        forged_edits = json.loads(json.dumps(base))
        for edit in forged_edits["content"]["gcr_edits"][:2]:
            edit["amount"] = "7"
        stripped = json.loads(json.dumps(base))
        del stripped["content"]["gcr_edits"]
        for label, value in (
            ("forged-edits", forged_edits),
            ("no-edits", stripped),
            ("other-amount", generator.record("confirmed", generator.send_content(amount_os=generator.OTHER_AMOUNT_OS))),
            ("failed", generator.record("failed")),
        ):
            with self.subTest(record=label):
                got = generator.found(value)["appliedTransfer"]
                for member in ("payerDebitOs", "payeeCreditOs", "committedBalances"):
                    self.assertEqual(want[member], got[member])

    def test_four_edit_record_without_committed_payment_is_refused(self):
        """A confirmed record carrying all four edits of its send proves no
        payment when the authenticated committed balances did not move: an
        honest zero authority is refused (handler `indeterminate`, consumer
        `fail`), and one that copies the amount over unchanged balances
        establishes nothing on either path."""
        for name, expected in (
            ("confirmed-four-edits-uncommitted-payment", "indeterminate"),
            ("confirmed-four-edits-authority-not-committed-change", "indeterminate"),
            ("consumer-four-edits-uncommitted-payment", "fail"),
            ("consumer-four-edits-authority-not-committed-change", "indeterminate"),
        ):
            with self.subTest(name=name):
                vector = self.cases[name]
                self.assertTrue(edits_match(vector["protocolInput"]["recordRead"]["record"]["content"]))
                self.assertEqual(expected, vector["expected"])
                self.assertEqual(expected, evaluate(vector)[0])
        unchanged = dict(generator.ROLLED_BACK)
        self.assertEqual(unchanged["payerBeforeOs"], unchanged["payerAfterOs"])
        self.assertEqual(unchanged["payeeBeforeOs"], unchanged["payeeAfterOs"])
        # Every passing vector, with its committed balances left unchanged:
        # copied figures prove nothing, honest zero figures refute.
        for vector in self.data["vectors"]:
            read = vector["protocolInput"].get("recordRead")
            if vector["expected"] != "pass" or not isinstance(read, dict) or "appliedTransfer" not in read:
                continue
            for label, figures in (("copied", None), ("honest-zero", ("0", "0"))):
                with self.subTest(name=vector["name"], authority=label):
                    mutated = json.loads(json.dumps(vector))
                    proof = mutated["protocolInput"]["recordRead"]["appliedTransfer"]
                    proof["committedBalances"] = dict(unchanged)
                    if figures is not None:
                        proof["payerDebitOs"], proof["payeeCreditOs"] = figures
                    result = evaluate(mutated)[0]
                    self.assertNotEqual("pass", result)
                    if vector["operation"] == "admit-evidence" and figures is not None:
                        self.assertEqual("fail", result)

    def test_contradicting_authority_never_overrides_a_failed_record(self):
        """DEM-7 and DEMOS-MAPPING §A.2 make a contradicting authority `fail`
        only for a bound `confirmed` record. A bound `failed` record keeps its
        DEM-4 (handler) or DEM-7 `failed` (consumer) outcome even though its
        authenticated authority shows the rolled-back, unchanged balances."""
        spec = SPEC.read_text(encoding="utf-8")
        demos = DEMOS.read_text(encoding="utf-8")
        self.assertIn("For a bound `confirmed` record, whatever its edits, independently authenticated applied-payment authority that contradicts them is `fail`", spec)
        self.assertIn("A bound `failed` record is decided by the two `failed` rules above, whatever the authority reports.", spec)
        self.assertIn("A bound `failed` record stays under DEM-4 for the handler and under DEM-7's `failed` rules for a consumer, whatever the authority reports.", demos)
        checked = 0
        for name, expected in (
            ("included-failed", "fail"),
            ("included-failed-plain-read", "indeterminate"),
            ("node2-included-failed-record", "indeterminate"),
            ("node2-failed-record-authenticated", "fail"),
            ("consumer-failed-fails", "fail"),
            ("consumer-failed-unauthenticated", "indeterminate"),
        ):
            with self.subTest(name=name):
                vector = self.cases[name]
                read = vector["protocolInput"]["recordRead"]
                self.assertEqual("failed", read["record"]["status"])
                self.assertIs(True, read["appliedTransferAuthenticated"])
                self.assertEqual(("0", "0"), committed_change(read["appliedTransfer"]))
                self.assertEqual(expected, vector["expected"])
                self.assertEqual(expected, evaluate(vector)[0])
                checked += 1
        # Every failed-record vector with an authority: dropping or keeping
        # the authority never changes its outcome.
        for vector in self.data["vectors"]:
            read = vector["protocolInput"].get("recordRead")
            if not (isinstance(read, dict) and isinstance(read.get("record"), dict)
                    and read["record"].get("status") == "failed" and "appliedTransfer" in read):
                continue
            with self.subTest(name=vector["name"]):
                without = json.loads(json.dumps(vector))
                del without["protocolInput"]["recordRead"]["appliedTransfer"]
                del without["protocolInput"]["recordRead"]["appliedTransferAuthenticated"]
                self.assertEqual(evaluate(vector)[0], evaluate(without)[0])
                checked += 1
        self.assertGreater(checked, 10)

    def test_confirmed_no_op_never_establishes_payment(self):
        """The pinned node applies a send without edits as a successful no-op:
        neither its unchanged committed balances nor an authority that reports
        a payment for it reaches success, on the handler or consumer path."""
        for name, expected in (
            ("confirmed-no-op-apply", "indeterminate"),
            ("confirmed-no-op-empty-edits", "indeterminate"),
            ("confirmed-no-op-copied-authority", "indeterminate"),
            ("consumer-confirmed-no-op-apply", "fail"),
            ("consumer-confirmed-no-op-copied-authority", "indeterminate"),
        ):
            with self.subTest(name=name):
                self.assertEqual(expected, self.cases[name]["expected"])
                self.assertEqual(expected, evaluate(self.cases[name])[0])
        self.assertEqual(("0", "0"), (
            self.cases["confirmed-no-op-apply"]["protocolInput"]["recordRead"]["appliedTransfer"]["payerDebitOs"],
            self.cases["confirmed-no-op-apply"]["protocolInput"]["recordRead"]["appliedTransfer"]["payeeCreditOs"],
        ))
        # A receipt producer that keeps every passing record's authority but
        # strips, empties or reshapes its edits never passes.
        for vector in self.data["vectors"]:
            if vector["expected"] != "pass" or "recordRead" not in vector["protocolInput"]:
                continue
            for label, edits in (("missing", None), ("empty", []), ("object", {}), ("payment-only", "first-two")):
                with self.subTest(name=vector["name"], edits=label):
                    mutated = json.loads(json.dumps(vector))
                    content = mutated["protocolInput"]["recordRead"]["record"]["content"]
                    if edits is None:
                        del content["gcr_edits"]
                    elif edits == "first-two":
                        content["gcr_edits"] = content["gcr_edits"][:2]
                    else:
                        content["gcr_edits"] = edits
                    self.assertNotEqual("pass", evaluate(mutated)[0])

    def test_record_spellings_that_project_alike_bind(self):
        """DEMOS-MAPPING §A.2: every spelling the node may serve projects to the
        same value, so a passing record read witnesses each one, on the handler
        and the consumer path."""
        for operation in ("classify-execution", "admit-evidence"):
            contents = [vector["protocolInput"]["recordRead"]["record"]["content"] for vector in self.data["vectors"]
                        if vector["operation"] == operation and vector["expected"] == "pass"]
            for label, present in (
                ("prefixed send argument", lambda c: c["data"][1]["args"][0].startswith("0x")),
                ("bare send argument", lambda c: not c["data"][1]["args"][0].startswith("0x")),
            ):
                with self.subTest(operation=operation, spelling=label):
                    self.assertTrue(any(present(c) for c in contents))
        contents = [vector["protocolInput"]["recordRead"]["record"]["content"] for vector in self.data["vectors"]
                    if vector["operation"] == "classify-execution" and vector["expected"] == "pass"]
        for label, present in (
            ("prefixed parties", lambda c: c["from"].startswith("0x") and c["to"].startswith("0x")),
            ("bare parties", lambda c: not c["from"].startswith("0x") and not c["to"].startswith("0x")),
            ("string nonce", lambda c: isinstance(c["nonce"], str)),
            ("integer nonce", lambda c: isinstance(c["nonce"], int)),
            ("number amount", lambda c: isinstance(c["amount"], int)),
            ("string amount", lambda c: isinstance(c["amount"], str)),
            ("2^53 - 1 number amount", lambda c: c["amount"] == SAFE_MAX),
        ):
            with self.subTest(spelling=label):
                self.assertTrue(any(present(c) for c in contents))
        # T is the send argument with 0x prefixed only when absent: a prefixed
        # argument's credit edit names it once, and a second prefix is no payment.
        for name in ("confirmed-prefixed-send-argument-binds", "consumer-prefixed-send-argument-admitted"):
            with self.subTest(name=name):
                content = self.cases[name]["protocolInput"]["recordRead"]["record"]["content"]
                argument = content["data"][1]["args"][0]
                self.assertEqual("0x" + generator.PAYEE_KEY, argument)
                self.assertEqual(argument, content["gcr_edits"][1]["account"])
                self.assertTrue(edits_match(content))
                self.assertEqual("pass", evaluate(self.cases[name])[0])
                doubled = json.loads(json.dumps(self.cases[name]))
                doubled["protocolInput"]["recordRead"]["record"]["content"]["gcr_edits"][1]["account"] = "0x" + argument
                self.assertFalse(edits_match(doubled["protocolInput"]["recordRead"]["record"]["content"]))
                self.assertEqual("indeterminate", evaluate(doubled)[0])
        # The 2^53 - 1 bound decodes as a number; one past it does not (JCS
        # cannot carry it in the corpus, so it is refused in memory).
        bound = json.loads(json.dumps(self.cases["confirmed-safe-max-number-amount-binds"]))
        record = bound["protocolInput"]["recordRead"]["record"]
        self.assertEqual(str(SAFE_MAX), decode(record, frozenset())["amountOs"])
        record["content"].update(amount=SAFE_MAX + 1, data=["native", {"nativeOperation": "send", "args": [generator.PAYEE_KEY, str(SAFE_MAX + 1)]}])
        self.assertIsNone(decode(record, frozenset()))
        self.assertEqual("indeterminate", evaluate(bound)[0])

    def test_node_pin_is_the_binding_attested_exact_clean_build(self):
        demos = DEMOS.read_text(encoding="utf-8")
        self.assertTrue(DEMOS_RECORD_PROFILE.endswith("@" + PINNED_BUILD["commit"]))
        self.assertEqual(PINNED_BUILD, self.data["demosProfile"]["nodeBuild"])
        self.assertIn("the binding configuration's own build attestation for each node", demos)
        self.assertIn("an attested build of another commit, and a build from a modified tree are each not that pin", demos)
        builds = {
            "self-reported": dict(PINNED_BUILD, source="self-reported"),
            "testnet-commit": dict(PINNED_BUILD, commit="ac8f45f02fc9c25082ce9b83595c2e3916b49c5a"),
            "short-commit": dict(PINNED_BUILD, commit=PINNED_BUILD["commit"][:7]),
            "dirty-tree": dict(PINNED_BUILD, tree="dirty"),
            "extra-member": dict(PINNED_BUILD, dirty=False),
            "label-only": "pinned",
            "missing": None,
        }
        for name in ("included-confirmed", "consumer-confirmed-gate-passes", "delivery-after-all-gates"):
            control = self.cases[name]
            self.assertEqual("pass", evaluate(control)[0])
            for label, build in builds.items():
                with self.subTest(name=name, build=label):
                    mutated = json.loads(json.dumps(control))
                    read = mutated["protocolInput"]["recordRead"]
                    if build is None:
                        del read["nodeBuild"]
                        read["nodeProfile"] = "pinned"
                    else:
                        read["nodeBuild"] = build
                    # The pin is what a plain read rests on (DEM-2, and DEM-7
                    # for a plain read). A record FV-5 authenticates (delivery
                    # needs one) is bound as the signed result carries it,
                    # whatever node served the read (DEM-7).
                    if name == "delivery-after-all-gates":
                        self.assertTrue(fv5_authenticated(read, mutated["protocolInput"], frozenset(),
                                                          mutated["protocolInput"]["signedEvidence"]["txRef"]))
                        self.assertEqual("pass", evaluate(mutated)[0])
                        self.assertNotEqual("pass", evaluate(mutated, {"consumer-fv5-record-binds-without-node-pin"})[0])
                    else:
                        self.assertNotEqual("pass", evaluate(mutated)[0])
        # Each member of the pin has its own refusing vector on both paths.
        for guard in ("node-build-attested", "node-build-commit", "node-build-clean-tree"):
            operations = {v["operation"] for v in self.data["vectors"] if guard in v["guards"]}
            self.assertLessEqual({"classify-execution", "admit-evidence"}, operations, guard)

    def test_only_confirm_then_broadcast_carries_the_signed_transaction(self):
        spec = SPEC.read_text(encoding="utf-8")
        section = spec[spec.index("#### 9.5.9 pay-dem"):spec.index("**Finality.**", spec.index("#### 9.5.9 pay-dem"))]
        self.assertNotIn("via SR-3 proxy attestation", section)
        self.assertIn("`pay-dem` has no SR-3 proxy submission", section)
        self.assertIn("These two calls are the profile's only submission route", section)
        control = self.cases["confirm-after-durable-retention"]
        self.assertEqual("pass", evaluate(control)[0])
        for request in ("sr3-proxy-submission", "wallet-direct-submission"):
            with self.subTest(request=request):
                vector = self.cases[request + "-refused"]
                self.assertEqual(("fail", {"broadcastPermitted": False}), evaluate(vector))
                self.assertEqual(["egress-only-confirm-then-broadcast"], vector["guards"])
                # The route alone differs from a permitted confirm request.
                self.assertEqual(dict(control["protocolInput"], request=request), vector["protocolInput"])

    def test_spec_mapping_and_workflow_make_the_rules_load_bearing(self):
        spec = SPEC.read_text(encoding="utf-8")
        demos = DEMOS.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("status is exactly `confirmed`", spec)
        self.assertIn("MUST NOT broadcast it again or broadcast a replacement transfer", spec)
        self.assertIn("verify the included\n  transaction record under §9.5.9 DEM-7", spec)
        self.assertIn('`errorClass: "substrate"`', spec)
        self.assertIn("(`pay-evm-erc20`, `pay-solana-spl`, `pay-ap2`, `pay-x402`, `pay-dem`)", spec)
        self.assertNotIn('the tx reached the terminal "included" state', spec)
        self.assertNotIn("differently typed", spec)
        self.assertIn("by itself it authorizes neither delivery nor *settlement accounting*", spec)
        self.assertIn("MUST NOT broadcast a transaction that the profile does not authenticate", spec)
        self.assertIn("authenticate the full result record independently", spec)
        self.assertIn("a controlled Demos key claim of the payer's party\n  bundle that the Agreement pins", spec)
        self.assertNotIn("authenticated as PB-1\n  authenticates that bundle", spec)
        self.assertIn("unavailable\n  execution-result authentication is `indeterminate`", spec)
        self.assertIn("*Signed transaction.*", demos)
        self.assertIn("SHA-256 of the UTF-8 `JSON.stringify(content)`", demos)
        self.assertIn("`nonceEnforcement` fork", demos)
        self.assertIn("`signatureDomain` preimage", demos)
        self.assertIn("requires a revision of this profile", demos)
        self.assertIn("DEM-2 and DEM-3", demos)
        self.assertIn("61b8e75aa8db5e408c49e1c3a89db4d673f45578", demos)
        # The node pin names one commit; a later release needs a profile revision.
        self.assertIn("a build of exactly that commit from an unmodified tree", demos)
        self.assertNotIn("declares the same semantics", demos)
        self.assertIn("**Native-send record profile (normative).**", demos)
        self.assertIn("generate_pay_dem_execution_vectors.py --check", workflow)
        profile = self.data["demosProfile"]
        self.assertEqual(DEMOS_RECORD_PROFILE + " (stabilisation)", profile["nodeSource"])
        self.assertIn(DEMOS_RECORD_PROFILE.split("@", 1)[1], demos)
        sdk, integrity = profile["sdk"].split(" ")
        self.assertIn(sdk.removeprefix("@kynesyslabs/demosdk@"), demos)
        self.assertIn(integrity, demos)
        self.assertIn("authenticate the committed native-send state transition independently", demos)
        self.assertIn("`network_fee`, `rpc_fee`, `additional_fee` and `rpc_address`, in that order", demos)
        self.assertIn("`timestamp` MUST be a positive JSON integer", demos)
        # The node normalises amounts before it compares edits; this profile
        # compares them exactly, which is stricter and fails closed.
        self.assertIn("refuses a native transaction whose edits still differ after it normalises their amounts", demos)
        self.assertIn("This profile is stricter: it compares the edits exactly as listed, as `JSON.stringify` "
                      "serializes them, members in order, for a record read as the node's own text", demos)
        self.assertIn("the order of an edit's members is not signed and carries no meaning there: the edits compare "
                      "by member name and value, in list order. A JSON number therefore compares by value", demos)
        self.assertIn("DEM-7 and FV-5 admit no record whose sender is none", demos)
        self.assertIn("A `?<parameters>` suffix is not part of that identity", demos)
        self.assertIn("so DEM-7 and FV-5 bind it under the record semantics pinned in the verifier's configuration "
                      "with no node pin", demos)
        self.assertIn("An applied transfer that an FV-5 execution result carries is not a separate authority", demos)
        self.assertIn("A bound `failed` record from an ordinary RPC read is `indeterminate`.", spec)
        self.assertIn("A Demos `txHash` has no legacy spelling", spec)

    def test_sb2_history_is_the_payees_delivery_input_only(self):
        """SB-2 is scoped to the presented set and DACS-5 derivations must be
        reproducible from their own contents. Only the payee's delivery check
        adds its own admissions, and it presents them as input; settlement
        accounting and the DACS-5 derivation never add unpresented history."""
        spec = SPEC.read_text(encoding="utf-8")
        dem7 = spec[spec.index("**(DEM-7) Consumer admission.**"):spec.index("**Finality.** Demos")]
        self.assertNotIn("across every `pay-dem` evidence set it has admitted", spec)
        self.assertIn("Every consumer applies SB-2 to `demos:{txHash}` over its presented evidence set", dem7)
        self.assertIn("Before delivery, the payee MUST present to that check, together with the evidence "
                      "for this phase, every `pay-dem` evidence it has itself admitted", dem7)
        self.assertIn("This history rule is the payee's delivery check alone.", dem7)
        self.assertIn("Settlement accounting, including the DACS-5 derivation, MUST NOT add evidence from outside "
                      "the presented set it accounts over", dem7)
        self.assertIn("Settlement accounting is any consumer's counting of evidence as the payment of its "
                      "`(jobId, phaseIndex)`", spec)
        self.assertIn("The check is scoped to the consumer's complete **presented evidence set**", spec)
        # A deriver that once admitted H for X still counts Y when only Y is
        # presented; the payee, which presents its own admission, does not deliver.
        derivation = self.cases["sb2-demos-unpresented-admission-not-added"]
        records, history = (derivation["protocolInput"][k] for k in ("records", "consumerAdmissions"))
        self.assertEqual([r["txRef"] for r in records], [a["txRef"] for a in history])
        self.assertNotEqual([r["jobId"] for r in records], [a["jobId"] for a in history])
        self.assertEqual("pass", evaluate(derivation)[0])
        self.assertEqual("indeterminate", evaluate(derivation, {"sb2-presented-set-only"})[0])
        payee = self.cases["delivery-hash-admitted-for-another-job"]
        self.assertEqual("indeterminate", evaluate(payee)[0])
        self.assertFalse(evaluate(payee)[1]["deliveryAuthorized"])
        # Every other derivation vector presents no extra history.
        for vector in self.data["vectors"]:
            if vector["operation"] == "resolve-settlement-group" and vector is not derivation:
                with self.subTest(name=vector["name"]):
                    self.assertEqual([], vector["protocolInput"]["consumerAdmissions"])

    def test_restated_outcomes_defer_to_dem7(self):
        """DEMOS-MAPPING §A.2 must not restate a consumer outcome that DEM-7
        decides otherwise: an authenticated contradicting authority is fail
        whatever the record's edits, for a fee-separated record too, while the
        handler stays indeterminate. DEM-6 names no resume of a terminal session."""
        spec = SPEC.read_text(encoding="utf-8")
        demos = DEMOS.read_text(encoding="utf-8")
        self.assertNotIn("is outside this profile and stays `indeterminate` under DEM-3 and DEM-7", demos)
        self.assertNotIn("its records stay `indeterminate`, never a false success", demos)
        self.assertIn("which DEM-7 decides `fail` whatever the record's edits", demos)
        self.assertIn("binds another genesis than the phase's pinned network decides `fail` under DEM-7", demos)
        self.assertIn("For a bound `confirmed` record, whatever its edits, independently authenticated "
                      "applied-payment authority that contradicts them is `fail`", spec)
        self.assertNotIn("a resume after `failed-substrate`", spec)
        self.assertNotIn("any resume after DEM-4", spec)
        self.assertIn("is a post-terminal read that changes no session state", spec)
        self.assertIn("the signed transaction itself and its hash, signed nonce", spec)
        consumer = self.cases["consumer-fee-separated-edits-uncommitted-payment"]
        handler = self.cases["confirmed-fee-separated-edits-uncommitted-payment"]
        for vector in (consumer, handler):
            with self.subTest(name=vector["name"]):
                read = vector["protocolInput"]["recordRead"]
                self.assertGreater(len(read["record"]["content"]["gcr_edits"]), 4)
                self.assertEqual(generator.committed_change(generator.ROLLED_BACK),
                                 (read["appliedTransfer"]["payerDebitOs"], read["appliedTransfer"]["payeeCreditOs"]))
        self.assertEqual("fail", evaluate(consumer)[0])
        self.assertEqual("indeterminate", evaluate(handler)[0])
        # Removing the edit check changes nothing: the authority decides first.
        self.assertEqual("fail", evaluate(consumer, {"confirmed-requires-send-edits"})[0])
        # A genesis replaced after signing: the authority names another genesis.
        replaced = json.loads(json.dumps(self.cases["consumer-confirmed-gate-passes"]))
        replaced["protocolInput"]["recordRead"]["appliedTransfer"]["genesisHash"] = "f" * 64
        self.assertEqual("fail", evaluate(replaced)[0])

    def test_the_payer_signs_only_what_dem7_will_bind(self):
        """The payer side and the consumer side apply one predicate (DEMOS-MAPPING
        §A.2): over every scheme and mechanism of a payer-bundle claim for the
        paying key, the DEM-1 gates (before signing, at the `confirm` and at the
        `broadcast`) permit exactly when DEM-7 binds the handler's own transfer.
        A gate that permits what DEM-7 refuses pays into a refusal: the transfer
        executes, the payee never delivers, and DEM-5 permits no replacement."""
        key = generator.PAYER_KEY
        sign = self.cases["sign-with-pinned-node-and-applied-payment-authority"]
        confirm = self.cases["confirm-after-durable-retention"]
        broadcast = self.cases["first-broadcast-after-durable-retention"]
        admit = self.cases["consumer-confirmed-gate-passes"]
        controls = ("presentation-signature", "sr1-linkage", "holder-binding", "demos-gcr-domain", "none")
        references = ("key:" + key, "did:demos:agent:" + key, "cci-xm:demos:mainnet:0x" + key, key, "0x" + key,
                      "key:" + key.upper(), "key:0x" + key, "key:" + generator.OTHER_KEY, "lei:529900T8BM49AURSDO55")
        permitted = set()
        for reference in references:
            for control in controls:
                claims = [{"claim": reference, "control": control}]
                with self.subTest(claim=reference, control=control):
                    verdicts = {}
                    for label, vector in (("sign", sign), ("confirm", confirm), ("broadcast", broadcast)):
                        changed = json.loads(json.dumps(vector))
                        changed["protocolInput"]["phase"]["payerKeyClaims"] = claims
                        verdicts[label] = evaluate(changed)[0] == "pass"
                    changed = json.loads(json.dumps(admit))
                    changed["protocolInput"]["phase"]["payerKeyClaims"] = claims
                    verdicts["dem7"] = evaluate(changed)[0] == "pass"
                    self.assertEqual(1, len(set(verdicts.values())), verdicts)
                    if verdicts["dem7"]:
                        permitted.add((reference, control))
        # Exactly one pair is a controlled Demos key claim of the paying key.
        self.assertEqual({("key:" + key, "presentation-signature")}, permitted)
        # Without the gates' own check, each signs for a key DEM-7 refuses.
        for vector, guard in ((sign, "pre-sign-paying-key-controlled"), (confirm, "broadcast-paying-key-controlled"),
                              (broadcast, "broadcast-paying-key-controlled")):
            changed = json.loads(json.dumps(vector))
            changed["protocolInput"]["phase"]["payerKeyClaims"] = [{"claim": "key:" + key, "control": "none"}]
            self.assertNotEqual("pass", evaluate(changed)[0])
            self.assertEqual("pass", evaluate(changed, {guard})[0])
        self.assertEqual("indeterminate", evaluate(admit | {"protocolInput": dict(
            admit["protocolInput"], phase=dict(admit["protocolInput"]["phase"],
                                               payerKeyClaims=[{"claim": "key:" + key, "control": "none"}]))})[0])
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("MUST check that the sender is the key of a *controlled Demos key claim* of the retained payer "
                      "bundle that `payer.bundleHash` pins", spec)

    def test_party_addresses_compare_by_their_pay_dem_projection(self):
        """A genuine payment to the payee's key passes every path whichever
        pay-dem spelling the Agreement used (the PB corpus's
        0x key, the APR corpus's DACS-1 DID, the bare key), and a spelling in
        no pay-dem form is error, never a comparison of spellings."""
        demos = DEMOS.read_text(encoding="utf-8")
        self.assertIn("A *pay-dem party address* is the authority side of that comparison", demos)
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("each as the DEMOS-MAPPING §A.2 *pay-dem party address* projects it", spec)
        self.assertIn("projection of a *controlled Demos key claim* of the payer's party bundle that the Agreement pins", spec)
        self.assertNotIn("authenticated as PB-1 authenticates that bundle", spec)
        self.assertIn("A Demos key claim is *controlled* only by the DACS-1 §6.3.2 step (6) mechanism that "
                      "DACS-1 defines for its scheme", demos)
        self.assertNotIn("selected `payer.payingKey`", spec)
        self.assertIn("and `payee.payeeAddress`, each as the DEMOS-MAPPING §A.2 *pay-dem party address*", spec)
        key = generator.PAYEE_KEY
        for name in ("first-broadcast-after-durable-retention", "consumer-confirmed-gate-passes",
                     "delivery-after-all-gates"):
            for spelling, expected in ((key, "pass"), ("0x" + key, "pass"), ("did:demos:agent:" + key, "pass"),
                                       ("0x" + key.upper(), "error"), ("did:demos:agent:0x" + key, "error"),
                                       ("did:key:" + key, "error"), ("0x" + key[:40], "error"), (None, "error")):
                with self.subTest(name=name, spelling=spelling):
                    case = json.loads(json.dumps(self.cases[name]))
                    case["protocolInput"]["phase"]["payeeAddress"] = spelling
                    self.assertEqual(expected, evaluate(case)[0])
                    if expected == "pass" and spelling != key:
                        # Comparing the spelling as given refuses a genuine payment.
                        self.assertNotEqual("pass", evaluate(case, {"phase-party-address-projects"})[0])
        # The PB and APR corpora's demos-native:DEM payout bindings are pay-dem
        # party addresses, so PB-1 byte equality and DEM-1/DEM-7 agree.
        security = ROOT / "conformance/vectors/security"
        bindings = set()
        for file_name in ("payee-destination-binding-v0.1.json", "alternative-payment-projection-v0.1.json"):
            text = (security / file_name).read_text(encoding="utf-8")
            bindings |= set(re.findall(r'"(?:0x[0-9a-f]{64}|did:demos:agent:[0-9a-f]{64})"', text))
        self.assertTrue(bindings)
        for binding in bindings:
            with self.subTest(binding=binding):
                self.assertIsNotNone(party_address(json.loads(binding), frozenset()))

    def test_pay_dem_rail_is_preflighted_before_selection_and_refused_as_substrate_at_settle(self):
        """No session commits to a pay-dem rail whose payer binding cannot
        execute it, whatever availability the rail shows, and
        a binding found missing at settle is RAV-R4 substrate, not a payer
        fault after the payee may already have delivered."""
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("For a `pay-dem` rail (§9.5.9) the preflight applies whatever the rail's availability, "
                      "`live` included", spec)
        self.assertIn("and so before Agreement signature and the PIPE-6 commitment, and MUST NOT select the rail for "
                      "the payer, or let the payer sign an Agreement on it, without it", spec)
        self.assertIn("MAY list, offer or select the rail", spec)
        self.assertIn("holds a controlled Demos key claim (DEMOS-MAPPING §A.2), since DEM-1 signs for no other key", spec)
        self.assertIn("one found missing at settle makes the rail non-operational for this payer under RAV-R4", spec)
        preflights = {name: case for name, case in self.cases.items() if case["operation"] == "rail-preflight"}
        self.assertEqual({"preflight-live-rail-with-binding", "preflight-live-rail-without-applied-payment-authority",
                          "preflight-live-rail-without-fork-attestation",
                          "preflight-live-rail-without-bft-final-trust",
                          "preflight-live-rail-without-execution-result-policy",
                          "preflight-operator-gated-rail-without-pinned-node",
                          "preflight-operator-gated-rail-with-binding",
                          "preflight-live-rail-with-rail-network-entry-among-several",
                          "preflight-bundle-controls-key-claim", "preflight-session-key-bundle-refused"}
                         | {"preflight-live-rail-with-" + suffix for suffix in (*NETWORK_VARIANTS, *UNUSABLE_TRUST)},
                         set(preflights))
        for availability in ("disabled", "failed", "mocked"):
            with self.subTest(availability=availability):
                case = json.loads(json.dumps(preflights["preflight-live-rail-with-binding"]))
                case["protocolInput"]["availability"] = availability
                self.assertEqual("fail", evaluate(case)[0])
        unknown = json.loads(json.dumps(preflights["preflight-live-rail-with-binding"]))
        unknown["protocolInput"]["availability"] = "Live"
        self.assertEqual("error", evaluate(unknown)[0])
        # RAV-R3 read literally gates only operator_gated, closed_data and
        # bilateral, and would select a live pay-dem rail its payer cannot pay on.
        live = preflights["preflight-live-rail-without-applied-payment-authority"]
        self.assertEqual("pass", evaluate(live, {"pay-dem-preflight-whatever-availability"})[0])
        for name, case in self.cases.items():
            if case["operation"] == "pre-sign-gate" and case["expected"] == "fail":
                with self.subTest(name=name):
                    self.assertEqual("substrate", case["want"]["errorClass"])

    def test_bft_final_trust_is_a_member_exactly_when_fv_verifies_under_it(self):
        """DEM-1 and RAV-R3 count the rail network's bft-final trust only when
        the FV verifier can verify the rail's inclusion under it: for every
        binding in the gate vectors, the gate's answer is FV's verdict on a
        genuine transfer's inclusion under that trust. Present trust that FV
        rejects (a set that is not the pinned one, keys that do not decode or
        alias one key) is refused, and a presence check would have sent it."""
        proof = generator.inclusion_proof()
        reference = proof["transactionRef"]
        checked = set()
        for name, vector in self.cases.items():
            protocol_input = vector["protocolInput"]
            if vector["operation"] not in {"pre-sign-gate", "broadcast-gate", "rail-preflight"}:
                continue
            rail = protocol_input["railNetwork"]
            trust = next((entry.get("bftFinalTrust") for entry in protocol_input["demosBinding"]
                          if {k: entry.get(k) for k in NETWORK} == rail), None)
            if not (isinstance(trust, dict) and set(trust) == NETWORK | BFT_FINAL_TRUST
                    and {k: trust[k] for k in NETWORK} == rail):
                continue
            with self.subTest(name=name):
                fv_trust = dict({k: trust[k] for k in BFT_FINAL_TRUST},
                                verificationTimeMs=generator.FINALITY_TRUST["verificationTimeMs"])
                verified = verify_transaction_inclusion(
                    proof, protocol_input["finalityProfile"], reference, fv_trust)[0] == "pass"
                self.assertEqual(verified, binding_members(protocol_input, frozenset())["bftFinalTrust"])
                checked.add(verified)
        self.assertEqual({True, False}, checked)
        for suffix in UNUSABLE_TRUST:
            for prefix in ("sign-with-", "confirm-with-", "broadcast-with-", "preflight-live-rail-with-"):
                with self.subTest(name=prefix + suffix):
                    vector = self.cases[prefix + suffix]
                    self.assertEqual("fail", vector["expected"])
                    self.assertTrue(binding_members(vector["protocolInput"],
                                                    {"bft-final-trust-verifies-profile"})["bftFinalTrust"])


if __name__ == "__main__":
    unittest.main()
