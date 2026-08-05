#!/usr/bin/env python3
"""Generate signed DACS-4 v0.6 SB-1 event-identity vectors.

The fixture seed is public test material. Every SettlementEvidence signature is
a genuine Ed25519 signature over ``dacs-evidence:v1:`` plus the canonical
unsigned-record hash. Negative signature-replay cases are signed before their
type discriminator or body is changed.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "settlement-event-identity-v0.6.json"
)
DOMAIN = "dacs-evidence:v1:"
SEED = bytes.fromhex("42" * 32)
SIGNER = "did:demos:agent:" + "42" * 32
EVM_TX = "ab" * 32
EVM_TX_2 = "cd" * 32
SOLANA_SIGNATURE = (
    "6pc4LiB8KHAPvbUbkozrTcPL5zXspYBdATv5raNDyVbhiKjrKokLb9o111kxTD5Kk"
    "PVd7UBSCcFcnWFkrJ82Hu6"
)
EVM_ASSET = "eip155:8453/erc20:0x00000000000000000000000000000000000000cc"
SOLANA_ASSET = "solana:devnet/spl:So11111111111111111111111111111111111111112"
EVM_PAYER = "0x00000000000000000000000000000000000000a1"
EVM_PAYEE = "0x00000000000000000000000000000000000000b2"
SOLANA_PAYER = "Buyer11111111111111111111111111111111111111"
SOLANA_PAYEE = "Seller1111111111111111111111111111111111111"


def canonical_bytes(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def hash_hex(value) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sign_evidence(evidence: dict) -> None:
    unsigned = {key: value for key, value in evidence.items() if key != "signature"}
    digest = hash_hex(unsigned)
    signature = Ed25519PrivateKey.from_private_bytes(SEED).sign(
        (DOMAIN + digest).encode("ascii")
    )
    evidence["signature"] = {
        "algorithm": "ed25519",
        "signer": SIGNER,
        "value": b64url(signature),
    }


def event(kind: str, index: int, *, matches: bool = True) -> dict:
    if kind == "solana":
        return {
            "ledger": "solana",
            "cluster": "devnet",
            "signature": SOLANA_SIGNATURE,
            "instructionIndex": index,
            "standard": "spl-transfer",
            "asset": SOLANA_ASSET,
            "payer": SOLANA_PAYER,
            "payee": SOLANA_PAYEE if matches else SOLANA_PAYER,
            "amount": "5",
        }
    return {
        "ledger": "evm",
        "chainId": 8453,
        "txHash": EVM_TX,
        "logIndex": index,
        "standard": "erc20-transfer",
        "asset": EVM_ASSET,
        "payer": EVM_PAYER,
        "payee": EVM_PAYEE if matches else EVM_PAYER,
        "amount": "5",
    }


def context(kind: str = "evm") -> dict:
    if kind == "solana":
        return {
            "asset": SOLANA_ASSET,
            "payer": SOLANA_PAYER,
            "payee": SOLANA_PAYEE,
            "amount": {"amount": "5", "currency": "SOL"},
        }
    return {
        "asset": EVM_ASSET,
        "payer": EVM_PAYER,
        "payee": EVM_PAYEE,
        "amount": {"amount": "5", "currency": "USDC"},
    }


def evidence(job_id: str, phase: str, tx_ref: dict) -> dict:
    record = {
        "evidenceVersion": "1",
        "jobId": job_id,
        "phase": phase,
        "outcome": "success",
        "paymentTxRefs": [copy.deepcopy(tx_ref)],
        "paymentAmount": (
            {"amount": "5", "currency": "SOL"}
            if phase == "pay-solana-spl"
            else {"amount": "5", "currency": "USDC"}
        ),
        "settlementFinality": {
            "model": "commitment-level" if phase == "pay-solana-spl" else "block-depth",
            **(
                {"finalityCommitmentLevel": "finalized"}
                if phase == "pay-solana-spl"
                else {"finalityBlocks": 12}
            ),
            "finalityObservedAt": 1785866400000,
        },
        "observedAt": 1785866400000,
    }
    sign_evidence(record)
    return record


def vector(
    name: str,
    expected: str,
    tx_ref: dict,
    ledger_events,
    *,
    job_id: str = "job-315-a",
    phase: str = "pay-evm-erc20",
    rail_id: str = "base-usdc",
    phase_index: int = 0,
    prior_claims: dict | None = None,
    verification_context: dict | None = None,
    expected_settlement_tx_id: str | None = None,
    note: str,
) -> dict:
    item = {
        "name": name,
        "expected": expected,
        "note": note,
        "anchorAddress": f"dacs4:payment:{job_id}:{rail_id}:{phase_index}",
        "phaseIndex": phase_index,
        "verificationContext": verification_context or context(
            "solana" if phase == "pay-solana-spl" else "evm"
        ),
        "ledgerEvents": ledger_events,
        "priorClaims": prior_claims or {},
        "settlementEvidence": evidence(job_id, phase, tx_ref),
    }
    if expected_settlement_tx_id is not None:
        item["expectedSettlementTxId"] = expected_settlement_tx_id
    return item


def build_vectors() -> list[dict]:
    evm_ref = {
        "kind": "evm-event", "chainId": 8453, "txHash": EVM_TX, "logIndex": 0,
    }
    solana_ref = {
        "kind": "solana-instruction",
        "cluster": "devnet",
        "signature": SOLANA_SIGNATURE,
        "instructionIndex": 2,
    }
    legacy_evm_ref = {"kind": "evm", "chainId": 8453, "txHash": EVM_TX}
    vectors = [
        vector(
            "current-evm-log-index",
            "pass",
            evm_ref,
            [event("evm", 0)],
            expected_settlement_tx_id=f"evm:8453:{EVM_TX}:0",
            note="a signed EVM log index selects the independently verified transfer",
        ),
        vector(
            "current-solana-instruction-index",
            "pass",
            solana_ref,
            [event("solana", 2)],
            phase="pay-solana-spl",
            rail_id="solana-devnet-sol",
            phase_index=2,
            verification_context=context("solana"),
            expected_settlement_tx_id=f"solana:devnet:{SOLANA_SIGNATURE}:2",
            note="a signed Solana instruction index selects the independently verified transfer",
        ),
        vector(
            "batched-evm-transfer-distinct-key",
            "pass",
            {**evm_ref, "logIndex": 1},
            [event("evm", 0), event("evm", 1)],
            phase_index=1,
            prior_claims={
                f"evm:8453:{EVM_TX}:0": {"jobId": "job-315-a", "phaseIndex": 0}
            },
            expected_settlement_tx_id=f"evm:8453:{EVM_TX}:1",
            note="two matching transfers in one envelope remain distinct because the signed log indexes differ",
        ),
        vector(
            "same-event-second-job-rejected",
            "fail",
            evm_ref,
            [event("evm", 0)],
            job_id="job-315-b",
            prior_claims={
                f"evm:8453:{EVM_TX}:0": {"jobId": "job-315-a", "phaseIndex": 0}
            },
            note="SB-2 rejects the same verified event under a second jobId",
        ),
        vector(
            "current-event-index-missing",
            "error",
            {"kind": "evm-event", "chainId": 8453, "txHash": EVM_TX},
            [event("evm", 0)],
            note="the current discriminator without its signed coordinate is malformed",
        ),
        vector(
            "current-event-index-negative",
            "error",
            {**evm_ref, "logIndex": -1},
            [event("evm", 0)],
            note="a negative signed coordinate is malformed and cannot mint a key",
        ),
        vector(
            "signed-index-ledger-mismatch",
            "fail",
            {**evm_ref, "logIndex": 7},
            [event("evm", 0), event("evm", 7, matches=False)],
            note="a valid signature cannot rescue an index that selects the wrong transfer",
        ),
        vector(
            "legacy-unambiguous-replay",
            "pass",
            legacy_evm_ref,
            [event("evm", 0), event("evm", 3, matches=False)],
            expected_settlement_tx_id=f"evm:8453:{EVM_TX}:0",
            note="one authenticated matching event permits a legacy event-level projection",
        ),
        vector(
            "legacy-ambiguous-replay",
            "indeterminate",
            legacy_evm_ref,
            [event("evm", 0), event("evm", 1)],
            note="two authenticated matching events leave a legacy envelope reference ambiguous",
        ),
        vector(
            "legacy-out-of-band-index-not-authority",
            "indeterminate",
            legacy_evm_ref,
            [event("evm", 0), event("evm", 1)],
            note="an unsigned caller index cannot disambiguate two matching legacy events",
        ),
        vector(
            "current-ledger-unavailable",
            "indeterminate",
            evm_ref,
            None,
            note="unavailable authenticated ledger evidence never becomes pass or counterparty failure",
        ),
        vector(
            "current-x402-event",
            "pass",
            {
                "kind": "x402-event",
                "httpResource": "https://merchant.example/resource/315",
                "paymentReceiptHash": "44" * 32,
                "settlementTxHash": EVM_TX,
                "chainId": 8453,
                "logIndex": 0,
                "protocolVersion": "2",
            },
            [event("evm", 0)],
            phase="pay-x402",
            rail_id="x402-default",
            verification_context={
                **context("evm"),
                "x402Receipt": {
                    "verified": True,
                    "paymentReceiptHash": "44" * 32,
                    "settlementTxHash": EVM_TX,
                    "chainId": 8453,
                },
            },
            expected_settlement_tx_id=f"evm:8453:{EVM_TX}:0",
            note="the signed x402 receipt fields and EVM event resolve to one event identity",
        ),
    ]

    stripped = vector(
        "event-discriminator-stripping",
        "fail",
        evm_ref,
        [event("evm", 0)],
        note="removing the new discriminator and coordinate after signing invalidates the evidence signature",
    )
    stripped_ref = stripped["settlementEvidence"]["paymentTxRefs"][0]
    stripped_ref["kind"] = "evm"
    del stripped_ref["logIndex"]
    vectors.append(stripped)

    replay = vector(
        "cross-type-signature-replay",
        "fail",
        evm_ref,
        [event("evm", 0)],
        note="an EVM-event signature replayed over a Solana-instruction record is invalid",
    )
    replay["settlementEvidence"]["phase"] = "pay-solana-spl"
    replay["settlementEvidence"]["paymentAmount"] = {"amount": "5", "currency": "SOL"}
    replay["settlementEvidence"]["paymentTxRefs"] = [copy.deepcopy(solana_ref)]
    replay["verificationContext"] = context("solana")
    replay["ledgerEvents"] = [event("solana", 2)]
    vectors.append(replay)

    no_match = vector(
        "legacy-no-matching-event",
        "fail",
        legacy_evm_ref,
        [event("evm", 0, matches=False)],
        note="a resolved legacy transaction with no matching settlement event fails",
    )
    vectors.append(no_match)

    vectors[9]["outOfBandEventIndex"] = 0
    return vectors


def build_document() -> dict:
    vectors = build_vectors()
    return {
        "set": "settlement-event-identity-v0.6",
        "spec": "DACS-4 §9.5.8 SB-1/SB-2 signed event identity and legacy replay",
        "hash": hash_hex(vectors),
        "count": len(vectors),
        "publicKey": Ed25519PrivateKey.from_private_bytes(SEED).public_key().public_bytes_raw().hex(),
        "vectors": vectors,
    }


def encoded() -> str:
    return json.dumps(build_document(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = encoded()
    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else None
    if args.write:
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if current != expected:
        print(f"stale: {OUTPUT.relative_to(ROOT)}")
        return 1
    print(f"OK — {OUTPUT.relative_to(ROOT)} is deterministic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
