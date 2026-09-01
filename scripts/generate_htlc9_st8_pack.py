#!/usr/bin/env python3
"""Deterministic generator for the HTLC-9 / ST-8 asymmetric-settlement pack.

Emits two signed ``SettlementEvidence`` fixtures (DACS-4 §9.5.4, §10.3.1 ST-8):

* ``conformance/fixtures/settlement/htlc9-asymmetric.json`` — the interim
  ``outcome: "failure"`` record (``dest-revealed-source-unclaimed``): the payer's
  destination-side ``htlc-reveal`` has reached finality, the payee's source-side
  claim has not landed yet. Non-terminal ``settle-asymmetric`` state.
* ``conformance/fixtures/settlement/htlc9-asymmetric-resolved.json`` — the ST-8
  ``:resolved`` record: ``outcome: "success"`` carrying ``settlementFinality``
  (``model: "htlc-reveal"``), ``paymentAmount``, the full ``htlc-lock`` +
  ``htlc-reveal`` + ``htlc-claim`` set, and ``supersedesEvidenceRef`` whose
  ``contentHash`` is the §B.2 content hash of the interim record. No amendment is
  used (DACS-4-SETTLE.md, "No ``correction`` amendment is used").

Keys are derived from fixed public test seeds (the same convention as the
``conformance/vectors/security`` generators), so the signatures are reproducible
and ``--check`` fails loudly if the committed bytes drift from the generator.
The signature is Ed25519 over ``"dacs-evidence:v1:" || sha256hex(JCS(record minus
signature))`` — CORE §B.7 single-hash form. String values are NFC-normalised via
``scripts/jcs.py`` (CF-1); member names are preserved.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import jcs  # noqa: E402

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FIXTURE_DIR = ROOT / "conformance" / "fixtures" / "settlement"
INTERIM_PATH = FIXTURE_DIR / "htlc9-asymmetric.json"
RESOLVED_PATH = FIXTURE_DIR / "htlc9-asymmetric-resolved.json"

EVIDENCE_DOMAIN = "dacs-evidence:v1:"
ORCHESTRATOR_SEED = bytes.fromhex("41" * 32)  # public test seed; never a production key

JOB_ID = "01HTLC9ASYMMETRIC000000000000"
SOURCE_CHAIN = 84532   # Base Sepolia: payer locks here, payee claims here
DEST_CHAIN = 80002     # Polygon Amoy: payer reveals the preimage here
CONTRACT = "0x0000000000000000000000000000000000000308"
LOCK_TX = "0x" + "aa" * 32
REVEAL_TX = "0x" + "bb" * 32
CLAIM_TX = "0x" + "cc" * 32
INTERIM_LOCATOR = "stor:evidence:htlc9"


def canonical_bytes(value) -> bytes:
    return jcs.canonicalize(value).encode("utf-8")


def content_hash_hex(record: dict) -> str:
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    return hashlib.sha256(canonical_bytes(unsigned)).hexdigest()


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def signer_ref(seed: bytes) -> str:
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return "cci:" + pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign(record: dict, seed: bytes) -> None:
    payload = EVIDENCE_DOMAIN.encode("ascii") + content_hash_hex(record).encode("ascii")
    record["signature"] = {
        "algorithm": "ed25519",
        "signer": signer_ref(seed),
        "value": b64url(Ed25519PrivateKey.from_private_bytes(seed).sign(payload)),
    }


def interim_record() -> dict:
    record = {
        "evidenceVersion": "1",
        "jobId": JOB_ID,
        "observedAt": 1760000100000,
        "outcome": "failure",
        "paymentTxRefs": [
            {"kind": "htlc-lock", "chainId": SOURCE_CHAIN, "contractAddress": CONTRACT, "lockTxHash": LOCK_TX},
            {"kind": "htlc-reveal", "chainId": DEST_CHAIN, "contractAddress": CONTRACT, "revealTxHash": REVEAL_TX},
        ],
        "phase": "pay-cross-chain-htlc",
        "reason": "dest-revealed-source-unclaimed",
    }
    sign(record, ORCHESTRATOR_SEED)
    return record


def resolved_record(interim: dict) -> dict:
    record = {
        "evidenceVersion": "1",
        "jobId": JOB_ID,
        "observedAt": 1760000300000,
        "outcome": "success",
        "paymentAmount": {"amount": "25", "currency": "USDC"},
        "paymentTxRefs": [
            {"kind": "htlc-lock", "chainId": SOURCE_CHAIN, "contractAddress": CONTRACT, "lockTxHash": LOCK_TX},
            {"kind": "htlc-reveal", "chainId": DEST_CHAIN, "contractAddress": CONTRACT, "revealTxHash": REVEAL_TX},
            {"kind": "htlc-claim", "chainId": SOURCE_CHAIN, "contractAddress": CONTRACT, "claimTxHash": CLAIM_TX},
        ],
        "phase": "pay-cross-chain-htlc",
        "settlementFinality": {"model": "htlc-reveal", "finalityObservedAt": 1760000290000},
        "supersedesEvidenceRef": {
            "kind": "storage-program",
            "locator": INTERIM_LOCATOR,
            "contentHash": "sha256:" + content_hash_hex(interim),
        },
    }
    sign(record, ORCHESTRATOR_SEED)
    return record


def build() -> dict[Path, dict]:
    interim = interim_record()
    resolved = resolved_record(interim)
    return {
        INTERIM_PATH: {
            "kind": "SettlementEvidenceCase",
            "settlementEvidence": interim,
            "specRefs": ["§9.5.4", "§9.7", "§10.3.1"],
        },
        RESOLVED_PATH: {
            "kind": "SettlementEvidenceCase",
            "settlementEvidence": resolved,
            "specRefs": ["§9.5.4", "§9.7", "§10.3.1"],
        },
    }


def render(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if committed fixtures differ from the generator")
    parser.add_argument("--write", action="store_true", help="write the fixtures")
    args = parser.parse_args(argv)
    built = build()
    if args.write:
        FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
        for path, data in built.items():
            path.write_text(render(data), encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
        return 0
    drift = [str(p.relative_to(ROOT)) for p, d in built.items()
             if not p.exists() or p.read_text(encoding="utf-8") != render(d)]
    if drift:
        print("htlc9 st8 pack DRIFT: " + ", ".join(drift))
        return 1
    print("htlc9 st8 pack OK (deterministic generator output, 2 fixtures)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
