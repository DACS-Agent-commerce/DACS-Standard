"""Execute the DACS-4 §9.5.9 DEM-1..DEM-7 pay-dem execution corpus."""

from __future__ import annotations

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
from settlement_finality_reference import DEMOS_RECORD_PROFILE  # noqa: E402


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
    "sign-requires-pinned-node",
    "sign-requires-applied-payment-authority",
    "sign-requires-gas-fee-separation-unscheduled",
    "binding-refusal-is-rail-unavailable",
    # DEM-1/RAV-R3 "for the phase's network": the rail's pinned network
    "binding-network-is-rail-network",
    "pinned-nodes-bind-rail-network",
    "applied-authority-binds-rail-network",
    "fork-attestation-binds-rail-genesis",
    # RAV-R3 for pay-dem, before rail selection
    "preflight-requires-binding",
    "preflight-selects-configured-rail",
    "pay-dem-preflight-whatever-availability",
    # DEMOS-MAPPING §A.2 pay-dem party address
    "phase-party-address-projects",
    "first-broadcast-allowed",
    "retention-before-first-egress",
    "egress-only-confirm-then-broadcast",
    "broadcast-requires-pinned-node",
    "broadcast-requires-applied-payment-authority",
    "broadcast-requires-gas-fee-separation-unscheduled",
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
    "no-cross-phase-reuse",
    # DEM-2 and the DEMOS-MAPPING §A.2 native-send record profile
    "node-build-attested",
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
    "apr-evidence-requires-authenticated-failure",
    "apr-evidence-from-authenticated-failure",
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
    "consumer-binds-payee",
    "consumer-binds-amount",
    "consumer-failed-refutes",
    "consumer-failed-requires-authentication",
    "consumer-authenticated-contradiction-fails",
    # DEM-7 composed with FV-5, SB-1, SB-2 and PB before delivery
    "delivery-requires-dem7",
    "delivery-requires-authenticated-record",
    "delivery-requires-fv",
    "delivery-requires-sb1",
    "delivery-requires-pb",
    "delivery-sb2-own-admissions",
    "delivery-requires-admission-index",
    "delivery-history-is-admission-index",
    "sb2-admitted-legacy-collapse",
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
PARTY_ADDRESS = re.compile(r"(?:0x|did:demos:agent:)?([0-9a-f]{64})")
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
REQUESTS =frozenset({"confirm-retained", "broadcast-retained", "broadcast-replacement"})
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
        if not (isinstance(nonce, int) and _safe_integer(nonce)):
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


def applied(read, projection, protocol_input, off) -> str:
    """DEMOS-MAPPING §A.2 applied-payment authority for the handler (DEM-3) and
    the consumer (DEM-7): it names the phase's network, the observed inclusion
    block ID, the projected transaction and parties, and a debit and credit of
    the OS amount. Without the network or block ID to compare it binds nothing."""
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
        inclusion = protocol_input.get("inclusionObservation")
        block_id = inclusion.get("blockId") if isinstance(inclusion, dict) else None
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
            and sends_payment(record, off) and "success-branch" not in off):
        return handler_result("pass", protocol_input, off)
    # DEM-4: only a bound failed record authenticated under FV-5 at its
    # bft-final inclusion is terminal. A plain RPC read of one is DEM-5: a
    # stale or dishonest pinned node can serve failed for an executed transfer.
    if status == "failed" and (is_bound or "failure-requires-binding" in off) and (
        read.get("authenticated") is True or "failure-requires-authentication" in off
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


def authenticated_proof(proof) -> bool:
    """The proof's failed record was authenticated under FV-5 at its
    bft-final inclusion; any other label, or none, is a plain read."""
    return isinstance(proof, dict) and proof.get("authentication") == "fv5-bft-final"


def resume(protocol_input: dict, off) -> tuple[str, dict]:
    proof = protocol_input["retainedFailureProof"]
    if proof is not None and "resume-reuses-failure-proof" not in off:
        if "resume-validates-failure-proof" in off or (
            valid_failure_proof(proof, protocol_input["retainedTransfer"], off)
            # A plain-read proof (an earlier draft's DEM-4) is never reused:
            # the resume re-reads the retained hash instead.
            and (authenticated_proof(proof) or "resume-requires-authenticated-proof" in off)
        ):
            return handler_result("fail", protocol_input, off)
    return classify(protocol_input, off)


def apr_evidence(protocol_input: dict, off) -> tuple[str, dict]:
    """A DEM-4 failure proof offered as APR `closed-cannot-settle`
    reconciliation evidence: only a bound failed record authenticated under
    FV-5 at its `bft-final` inclusion qualifies, never a plain RPC read."""
    refused = ("indeterminate", {"reconciliationEvidence": False})
    proof = protocol_input["retainedFailureProof"]
    if not valid_failure_proof(proof, protocol_input["retainedTransfer"], off):
        return refused
    authenticated = authenticated_proof(proof)
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
    match = PARTY_ADDRESS.fullmatch(value) if isinstance(value, str) else None
    return match[1] if match else None


BINDING = ("pinnedNodes", "appliedPaymentAuthority", "gasFeeSeparation")
# Each binding that is not the rail network's, and the guard that refuses it.
NETWORK_VARIANTS = {
    "binding-for-another-network": "binding-network-is-rail-network",
    "binding-for-replaced-genesis": "binding-network-is-rail-network",
    "pinned-nodes-for-another-network": "pinned-nodes-bind-rail-network",
    "applied-authority-for-another-network": "applied-authority-binds-rail-network",
    "fork-attestation-of-another-genesis": "fork-attestation-binds-rail-genesis",
}
UNSELECTABLE = frozenset({"disabled", "failed", "mocked"})
RAV_R3_GATED = frozenset({"operator_gated", "closed_data", "bilateral"})


def _network(value):
    """A (networkId, genesisHash) pair of non-empty strings, or None."""
    if (isinstance(value, dict) and set(value) == NETWORK
            and all(isinstance(value[k], str) and value[k] for k in NETWORK)):
        return dict(value)
    return None


def binding_members(protocol_input: dict, off) -> dict[str, bool]:
    """DEM-1/RAV-R3: which of the three members the payer's Demos binding
    holds for the rail's network. That network is the pinned RailDefinition's
    `consumerFinalityProfile.settlement` (`railNetwork`), never one the
    binding supplies; the binding entry is the one for that network, and a
    member counts only when it names exactly that network and genesis."""
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
    ):
        value = entry.get(member)
        if not (isinstance(value, dict) and set(value) == NETWORK | extra):
            continue
        if guard not in off and {k: value[k] for k in NETWORK} != network:
            continue
        if extra and value["activationHeight"] is not None:
            continue
        held[member] = True
    return held


def rail_preflight(protocol_input: dict, off) -> tuple[str, dict]:
    """RAV-R3 for a new production session, before rail selection and so
    before Agreement signature and the PIPE-6 commitment: a `pay-dem` rail is
    selectable only when the payer's Demos binding holds DEM-1's three
    members for the rail's network, whatever availability the rail shows."""
    availability = protocol_input["availability"]
    if availability not in UNSELECTABLE | RAV_R3_GATED | {"live"}:
        return "error", {"railSelectable": False}
    if availability in UNSELECTABLE:
        return "fail", {"railSelectable": False}
    gated = availability in RAV_R3_GATED or "pay-dem-preflight-whatever-availability" not in off
    if gated and "preflight-requires-binding" not in off and not all(binding_members(protocol_input, off).values()):
        return "fail", {"railSelectable": False}
    if "preflight-selects-configured-rail" in off:
        return "fail", {"railSelectable": False}
    return "pass", {"railSelectable": True}


def pre_sign_gate(protocol_input: dict, off) -> tuple[str, dict]:
    """DEM-1 before signing: a Demos binding without pinned nodes, an
    applied-payment authority or a genesis attestation that `gasFeeSeparation`
    is unscheduled cannot reach DEM-3 success. The RAV-R3 preflight checked
    the binding before the rail was selected, so at settle the rail is
    non-operational for this payer: RAV-R4 substrate, and nothing is signed."""
    held = binding_members(protocol_input, off)
    for guard, member in (
        ("sign-requires-pinned-node", "pinnedNodes"),
        ("sign-requires-applied-payment-authority", "appliedPaymentAuthority"),
        ("sign-requires-gas-fee-separation-unscheduled", "gasFeeSeparation"),
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


def dem7(protocol_input: dict, off) -> str:
    """DEM-7 consumer gate, including the payee before delivery."""
    if (
        "consumer-requires-confirmed-record" in off
        and protocol_input["statusIndex"] == "included"
    ):
        return "pass"
    phase = protocol_input["phase"]
    payer, payee = (party_address(phase.get(field), off) for field in ("payerPayingKey", "payeeAddress"))
    if payer is None or payee is None:
        return "error"
    read = protocol_input["recordRead"]
    record = read.get("record") if read.get("state") == "found" else None
    projection = decode(record, off) if record is not None else None
    if projection is None or not pinned(read, off):
        return "indeterminate"
    reference = protocol_input["signedEvidence"]["txRef"]
    expected_values = {
        "txHash": reference["txHash"],
        "blockNumber": reference["blockNumber"],
        "sender": payer,
        "recipient": payee,
        "amountOs": _canonical(phase["amountOs"]),
    }
    is_bound = all(
        projection[field] == value or f"consumer-binds-{guard}" in off
        for (field, value), guard in zip(expected_values.items(), ("hash", "block", "payer", "payee", "amount"))
    )
    status = projection["status"]
    if is_bound and is_confirmed(status, off):
        decision = applied(read, projection, protocol_input, off)
        if decision != "pass":
            return "indeterminate" if "consumer-authenticated-contradiction-fails" in off else decision
        if not sends_payment(record, off):
            return "indeterminate"
        return "indeterminate" if "consumer-admits-confirmed" in off else "pass"
    if is_bound and status == "failed" and (
        read.get("authenticated") is True or "consumer-failed-requires-authentication" in off
    ):
        return "indeterminate" if "consumer-failed-refutes" in off else "fail"
    if (
        not is_bound
        and read.get("authenticated") is True
        and "consumer-authenticated-contradiction-fails" not in off
    ):
        return "fail"
    return "indeterminate"


def admit(protocol_input: dict, off) -> tuple[str, dict]:
    verdict = dem7(protocol_input, off)
    return verdict, {"dem7GatePassed": verdict == "pass", "deliveryAuthorized": False}


def admission_index(index) -> bool:
    """A snapshot of the payee's durable admission index: its revision and
    every admission it holds."""
    return (
        isinstance(index, dict)
        and set(index) == {"revision", "admissions"}
        and isinstance(index["revision"], int)
        and _safe_integer(index["revision"])
        and isinstance(index["admissions"], list)
        and all(isinstance(admission, dict) for admission in index["admissions"])
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
        protocol_input["recordRead"].get("authenticated") is not True
        and "delivery-requires-authenticated-record" not in off
    ):
        return result("indeterminate")
    for name in ("fv", "sb1", "pb"):
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
    if not admission_index(index):
        if "delivery-requires-admission-index" not in off:
            return result("error")
    elif history(admissions) != history(index["admissions"]) and "delivery-history-is-admission-index" not in off:
        return result("error")
    # SB-1 projects every admitted reference, collapsing a verified legacy
    # spelling, before SB-2 compares; one that cannot project is malformed.
    presented = demos_id(protocol_input["signedEvidence"]["txRef"], off)
    keys = [
        demos_id(admitted["txRef"], off,
                 legacy=admitted.get("legacy") is True and "sb2-admitted-legacy-collapse" not in off)
        for admitted in admissions
    ]
    if (presented is None or None in keys) and "sb2-admitted-malformed-error" not in off:
        return result("error")
    others = [
        admitted for admitted, key in zip(admissions, keys)
        if key is not None and key == presented
        and ({k: admitted[k] for k in tuple_} != tuple_ or "sb2-same-tuple-idempotent" in off)
    ]
    if others and "delivery-sb2-own-admissions" not in off:
        return result("indeterminate")
    return result("pass")


def demos_id(reference, off, *, legacy=False):
    if not (isinstance(reference, dict) and set(reference) == {"kind", "txHash", "blockNumber"}
            and reference["kind"] == "demos" and _safe_integer(reference["blockNumber"])):
        return None
    value = reference["txHash"]
    if not isinstance(value, str):
        return None
    if "sb1-demos-shape" in off:
        return "demos:" + value
    if legacy or "sb1-demos-canonical" in off:
        value = value.removeprefix("0x").lower()
    if not HASH.fullmatch(value):
        return None
    return "demos:" + (str(reference["blockNumber"]) if "sb1-demos-id" in off else value)


def project_id(protocol_input, off):
    key = demos_id(protocol_input["txRef"], off, legacy=protocol_input.get("legacy", False))
    return ("pass" if key else "error"), {"settlementTxId": key}


def resolve_group(protocol_input, off):
    """SB-2 over the presented records only: settlement accounting and the
    DACS-5 derivation never add the consumer's other admissions."""
    records = protocol_input["records"]
    if "sb2-presented-set-only" in off:
        # The wrong implementation adds its own earlier admissions, so its
        # result cannot be reproduced from the presented set.
        records = records + protocol_input["consumerAdmissions"]
    keys = [demos_id(record["txRef"], off, legacy=record.get("legacy", False)) for record in records]
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
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {vector["name"]: vector for vector in cls.data["vectors"]}

    def test_committed_file_is_deterministic(self):
        self.assertEqual(VECTORS.read_text(encoding="utf-8"), generator.rendered())

    def test_corpus_hash_is_jcs_bound_and_names_are_unique(self):
        encoded = canonicalize(self.data["vectors"]).encode("utf-8")
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), self.data["hash"])
        self.assertEqual(self.data["count"], len(self.data["vectors"]))
        self.assertEqual(self.data["count"], len(self.cases))
        # Every vector survives a JCS round trip unchanged, so a JavaScript
        # JSON.parse reader sees the same values as this oracle.
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                self.assertEqual(vector, json.loads(canonicalize(vector)))

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
            for name in ("generate_pay_dem_execution_vectors.py", "jcs.py", "demos_json.py"):
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
        self.assertNotIn("authenticated", self.cases["node2-included-failed-record"]["protocolInput"]["recordRead"])
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
                          "delivery-to-did-payee-address", "delivery-from-0x-paying-key"}, delivered)
        for name in delivered:
            protocol_input = self.cases[name]["protocolInput"]
            self.assertIs(True, protocol_input["recordRead"]["authenticated"])
            self.assertEqual({"fv": "pass", "sb1": "pass", "pb": "pass"}, protocol_input["otherGates"])

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
                          "broadcast-with-rail-network-entry-among-several",
                          "broadcast-to-0x-payee-address", "broadcast-to-did-payee-address",
                          "broadcast-from-did-paying-key", "confirm-after-durable-retention",
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
        self.assertIn("Demos binding without pinned nodes, an applied-payment authority or a genesis attestation that "
                      "`gasFeeSeparation` is unscheduled, found at settle → `substrate`", spec)
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
                          "sign-with-rail-network-entry-among-several"}
                         | {"sign-with-" + suffix for suffix in NETWORK_VARIANTS}, set(presign))
        for name, vector in presign.items():
            with self.subTest(name=name):
                self.assertEqual({"phase", "railNetwork", "demosBinding"}, set(vector["protocolInput"]))
                self.assertEqual(generator.NETWORK, vector["protocolInput"]["railNetwork"])
                if vector["expected"] == "pass":
                    self.assertEqual(("pass", {"signPermitted": True, "ok": None, "errorClass": None}), evaluate(vector))
                    continue
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
                if len(differs) == 1 and rest == {k: v for k, v in control["protocolInput"].items() if k != "recordRead"}:
                    with self.subTest(name=name):
                        # Figures without their committed change prove nothing either way.
                        self.assertEqual("indeterminate" if differs == {"committedBalances"} else refused,
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

    def test_admitted_legacy_spellings_collapse_before_sb2(self):
        base = self.cases["delivery-hash-admitted-for-another-job"]
        tx_hash = base["protocolInput"]["signedEvidence"]["txRef"]["txHash"]
        for spelling in ("0x" + tx_hash, tx_hash.upper(), "0x" + tx_hash.upper()):
            for legacy, verdict in ((True, "indeterminate"), (False, "error"), (None, "error")):
                with self.subTest(spelling=spelling[:6], legacy=legacy):
                    case = json.loads(json.dumps(base))
                    # The presented history and the index snapshot hold the same admission.
                    for admission in (case["protocolInput"]["consumerAdmissions"][0],
                                      case["protocolInput"]["admissionIndex"]["admissions"][0]):
                        admission["txRef"]["txHash"] = spelling
                        if legacy is not None:
                            admission["legacy"] = legacy
                    expected, want = evaluate(case)
                    self.assertEqual(verdict, expected)
                    self.assertFalse(want["deliveryAuthorized"])
                    self.assertFalse(want["settlementAccounting"])
        # The same spelling for the same tuple is still idempotent.
        same = json.loads(json.dumps(self.cases["delivery-same-tuple-readmitted"]))
        for admission in (same["protocolInput"]["consumerAdmissions"][0],
                          same["protocolInput"]["admissionIndex"]["admissions"][0]):
            admission["txRef"]["txHash"] = "0x" + tx_hash.upper()
            admission["legacy"] = True
        self.assertEqual("pass", evaluate(same)[0])
        group = self.cases["sb2-demos-legacy-spelling-collision"]
        self.assertEqual(["indeterminate", "indeterminate"],
                         [record["decision"] for record in evaluate(group)[1]["records"]])

    def test_only_an_authenticated_failed_record_refutes_evidence(self):
        self.assertEqual("fail", evaluate(self.cases["consumer-failed-fails"])[0])
        self.assertIs(True, self.cases["consumer-failed-fails"]["protocolInput"]["recordRead"]["authenticated"])
        unauthenticated = self.cases["consumer-failed-unauthenticated"]
        self.assertEqual("indeterminate", evaluate(unauthenticated)[0])
        plain = json.loads(json.dumps(unauthenticated))
        del plain["protocolInput"]["recordRead"]["authenticated"]
        self.assertEqual("indeterminate", evaluate(plain)[0])

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
        self.assertIn("An FV `fail` result alone does not show both", spec)
        terminal = 0
        for vector in self.data["vectors"]:
            if vector["operation"] not in {"classify-execution", "resume-phase"} or vector["expected"] != "fail":
                continue
            with self.subTest(name=vector["name"]):
                value = vector["protocolInput"]
                proof = value.get("retainedFailureProof")
                if proof is not None:
                    self.assertEqual("fv5-bft-final", proof["authentication"])
                    plain = json.loads(json.dumps(vector))
                    plain["protocolInput"]["retainedFailureProof"]["authentication"] = "rpc-read"
                else:
                    self.assertIs(True, value["recordRead"]["authenticated"])
                    plain = json.loads(json.dumps(vector))
                    del plain["protocolInput"]["recordRead"]["authenticated"]
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
        # After that plain-read failure, a later re-read of the retained hash
        # finds the executed transfer: success, never a reused failure proof.
        later = self.cases["resume-plain-read-failure-then-authenticated-confirmed"]
        self.assertEqual("rpc-read", later["protocolInput"]["retainedFailureProof"]["authentication"])
        self.assertEqual("pass", evaluate(later)[0])
        self.assertEqual("fail", evaluate(later, {"resume-requires-authenticated-proof"})[0])
        self.assertEqual("indeterminate", evaluate(self.cases["resume-plain-read-failure-proof-not-reused"])[0])

    def test_restart_makes_a_retained_transfer_maybe_broadcast(self):
        """DEM-6: a crash can fall between a call that carried the signed
        bytes and its journal entry, so after a (re)start a retained transfer
        is maybe-broadcast whatever state the handler recorded."""
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("a transfer the handler finds retained when it starts or restarts MUST be treated as "
                      "possibly broadcast, whatever progress its journal records.", spec)
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
        self.assertIn("for `pay-dem`, only a refusal found before the signed transfer's first egress or a DEM-4 "
                      "proven failure, nothing else (§9.5.9)", pc4)
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
                    self.assertTrue(edits_match(read["record"]["content"]))
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
        self.assertIn("primary party signing key\n  MUST NOT substitute", spec)
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
        self.assertIn("refuses a native transaction whose edits differ", demos)
        self.assertIn("A bound `failed` record from an ordinary RPC read is `indeterminate`.", spec)
        self.assertIn("collapsing a verified legacy spelling", spec)

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

    def test_party_addresses_compare_by_their_pay_dem_projection(self):
        """Cold review P1-1: a genuine payment to the payee's key passes every
        path whichever pay-dem spelling the Agreement used (the PB corpus's
        0x key, the APR corpus's DACS-1 DID, the bare key), and a spelling in
        no pay-dem form is error, never a comparison of spellings."""
        demos = DEMOS.read_text(encoding="utf-8")
        self.assertIn("A *pay-dem party address* is the authority side of that comparison", demos)
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("each as the DEMOS-MAPPING §A.2 *pay-dem party address* projects it", spec)
        self.assertIn("projections of the authenticated phase's selected `payer.payingKey` and `payee.payeeAddress`", spec)
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
        """Cold review P1-2: no session commits to a pay-dem rail whose payer
        binding cannot execute it, whatever availability the rail shows, and
        a binding found missing at settle is RAV-R4 substrate, not a payer
        fault after the payee may already have delivered."""
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("For a `pay-dem` rail (§9.5.9) the preflight applies whatever the rail's availability, "
                      "`live` included", spec)
        self.assertIn("so before Agreement signature and the PIPE-6 commitment, and MUST NOT select or offer the rail "
                      "without it", spec)
        self.assertIn("one found missing at settle makes the rail non-operational for this payer under RAV-R4", spec)
        preflights = {name: case for name, case in self.cases.items() if case["operation"] == "rail-preflight"}
        self.assertEqual({"preflight-live-rail-with-binding", "preflight-live-rail-without-applied-payment-authority",
                          "preflight-live-rail-without-fork-attestation",
                          "preflight-operator-gated-rail-without-pinned-node",
                          "preflight-operator-gated-rail-with-binding",
                          "preflight-live-rail-with-rail-network-entry-among-several"}
                         | {"preflight-live-rail-with-" + suffix for suffix in NETWORK_VARIANTS}, set(preflights))
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
            if case["operation"] == "pre-sign-gate" and case["expected"] != "pass":
                with self.subTest(name=name):
                    self.assertEqual("substrate", case["want"]["errorClass"])


if __name__ == "__main__":
    unittest.main()
