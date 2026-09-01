#!/usr/bin/env python3
"""Verify the HTLC-9 / ST-8 asymmetric-settlement pack (DACS-4 §9.5.4, §10.3.1).

Two signed ``SettlementEvidence`` fixtures form one supersession pair:

* the interim ``outcome: "failure"`` record (``dest-revealed-source-unclaimed``);
* the ST-8 ``:resolved`` ``outcome: "success"`` record whose
  ``supersedesEvidenceRef.contentHash`` MUST equal the §B.2 content hash of the
  interim record.

This verifier is executable, not a shape check: each record's Ed25519 signature
is verified over ``"dacs-evidence:v1:" || sha256hex(JCS(record minus signature))``
against the ``cci:<pubkey-hex>`` signer, and the supersession hash is recomputed.
No amendment of any kind is accepted — ST-8 resolution is a same-phase
supersession, not a ``correction`` (DACS-4-SETTLE.md: "No ``correction``
amendment is used").
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import jcs  # noqa: E402

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIXTURE_DIR = ROOT / "conformance" / "fixtures" / "settlement"
DEFAULT_INTERIM = FIXTURE_DIR / "htlc9-asymmetric.json"
DEFAULT_RESOLVED = FIXTURE_DIR / "htlc9-asymmetric-resolved.json"

EVIDENCE_DOMAIN = "dacs-evidence:v1:"
CD1_AMOUNT = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$")
FORBIDDEN_KEYS = {"settlementAmendment", "amendmentType", "amendmentRefs", "amendsEvidenceRef", "refundAmount"}


def fail(path: Path, message: str) -> str:
    try:
        label = path.resolve().relative_to(ROOT)
    except ValueError:
        label = path
    return f"{label}: {message}"


def content_hash_hex(record: dict) -> str:
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    return hashlib.sha256(jcs.canonicalize(unsigned).encode("utf-8")).hexdigest()


def is_attestation_ref(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("kind"), str)
        and isinstance(value.get("locator"), str)
        and isinstance(value.get("contentHash"), str)
        and value["contentHash"].startswith("sha256:")
        and len(value["contentHash"].removeprefix("sha256:")) == 64
    )


def verify_signature(record: dict) -> str | None:
    """Return an error string, or None when the Ed25519 signature verifies."""
    sig = record.get("signature")
    if not isinstance(sig, dict):
        return "signature MUST be an object"
    if sig.get("algorithm") != "ed25519":
        return "signature.algorithm MUST be ed25519"
    signer = sig.get("signer")
    if not isinstance(signer, str) or not re.fullmatch(r"cci:[0-9a-f]{64}", signer):
        return "signature.signer MUST be cci:<64 lowercase hex> (Ed25519 public key)"
    value = sig.get("value")
    if not isinstance(value, str) or not value or "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        return "signature.value MUST be unpadded base64url"
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer.removeprefix("cci:")))
        payload = EVIDENCE_DOMAIN.encode("ascii") + content_hash_hex(record).encode("ascii")
        public.verify(raw, payload)
    except (InvalidSignature, ValueError):
        return "signature does not verify over dacs-evidence:v1: || sha256(JCS(record minus signature))"
    return None


def _walk_keys(obj: Any):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _walk_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_keys(v)


def load_case(path: Path) -> tuple[dict | None, list[str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, [fail(path, "fixture file not found")]
    except json.JSONDecodeError as exc:
        return None, [fail(path, f"invalid JSON: {exc}")]
    errors: list[str] = []
    if data.get("kind") != "SettlementEvidenceCase":
        errors.append(fail(path, f"kind MUST be SettlementEvidenceCase, got {data.get('kind')!r}"))
    evidence = data.get("settlementEvidence")
    if not isinstance(evidence, dict):
        return None, errors + [fail(path, "settlementEvidence MUST be an object")]
    forbidden = FORBIDDEN_KEYS & set(_walk_keys(evidence))
    if forbidden:
        errors.append(fail(path, "ST-8 supersession MUST NOT carry amendment fields: " + ", ".join(sorted(forbidden))))
    if evidence.get("evidenceVersion") != "1":
        errors.append(fail(path, "evidenceVersion MUST be '1'"))
    if evidence.get("phase") != "pay-cross-chain-htlc":
        errors.append(fail(path, "phase MUST be pay-cross-chain-htlc"))
    if not isinstance(evidence.get("jobId"), str) or not evidence["jobId"]:
        errors.append(fail(path, "jobId MUST be a non-empty string"))
    if not isinstance(evidence.get("observedAt"), int) or isinstance(evidence.get("observedAt"), bool):
        errors.append(fail(path, "observedAt MUST be an integer unix-ms"))
    sig_err = verify_signature(evidence)
    if sig_err:
        errors.append(fail(path, sig_err))
    return evidence, errors


def txref_kinds(evidence: dict) -> list[str]:
    refs = evidence.get("paymentTxRefs")
    if not isinstance(refs, list):
        return []
    return [r.get("kind") for r in refs if isinstance(r, dict)]


def validate_interim(path: Path) -> tuple[dict | None, list[str]]:
    evidence, errors = load_case(path)
    if evidence is None:
        return None, errors
    if evidence.get("outcome") != "failure":
        errors.append(fail(path, "interim HTLC-9 evidence MUST have outcome failure"))
    if evidence.get("reason") != "dest-revealed-source-unclaimed":
        errors.append(fail(path, "interim evidence MUST carry reason dest-revealed-source-unclaimed"))
    kinds = txref_kinds(evidence)
    if "htlc-reveal" not in kinds:
        errors.append(fail(path, "paymentTxRefs MUST include an htlc-reveal txRef proving preimage disclosure"))
    if "htlc-claim" in kinds:
        errors.append(fail(path, "interim evidence MUST NOT carry an htlc-claim (that is the resolved record)"))
    if "settlementFinality" in evidence:
        errors.append(fail(path, "interim failure evidence MUST NOT carry settlementFinality"))
    return evidence, errors


def validate_resolved(path: Path, interim: dict | None) -> list[str]:
    evidence, errors = load_case(path)
    if evidence is None:
        return errors
    if evidence.get("outcome") != "success":
        errors.append(fail(path, "ST-8 resolved evidence MUST have outcome success"))
    kinds = txref_kinds(evidence)
    for needed in ("htlc-lock", "htlc-reveal", "htlc-claim"):
        if needed not in kinds:
            errors.append(fail(path, f"resolved evidence MUST carry the {needed} txRef"))
    claim = next((r for r in evidence.get("paymentTxRefs", []) if isinstance(r, dict) and r.get("kind") == "htlc-claim"), None)
    if claim is not None and not isinstance(claim.get("claimTxHash"), str):
        errors.append(fail(path, "htlc-claim txRef MUST carry claimTxHash"))
    fin = evidence.get("settlementFinality")
    if not isinstance(fin, dict) or fin.get("model") != "htlc-reveal":
        errors.append(fail(path, "resolved evidence MUST carry settlementFinality.model == htlc-reveal (PC-6)"))
    elif not isinstance(fin.get("finalityObservedAt"), int) or isinstance(fin.get("finalityObservedAt"), bool):
        errors.append(fail(path, "settlementFinality.finalityObservedAt MUST be an integer unix-ms"))
    amount = evidence.get("paymentAmount")
    if not isinstance(amount, dict) or not isinstance(amount.get("currency"), str):
        errors.append(fail(path, "resolved evidence MUST carry paymentAmount (REQUIRED on success-outcome records)"))
    elif not isinstance(amount.get("amount"), str) or not CD1_AMOUNT.fullmatch(amount["amount"]) or amount["amount"] == "0":
        errors.append(fail(path, "paymentAmount.amount MUST be a positive canonical decimal string (CD-1)"))
    ref = evidence.get("supersedesEvidenceRef")
    if not is_attestation_ref(ref):
        errors.append(fail(path, "resolved evidence MUST carry supersedesEvidenceRef (AttestationRef) to the interim record"))
    elif interim is not None:
        expected = "sha256:" + content_hash_hex(interim)
        if ref["contentHash"] != expected:
            errors.append(fail(path, "supersedesEvidenceRef.contentHash MUST equal the interim record's §B.2 content hash"))
        if interim.get("jobId") != evidence.get("jobId"):
            errors.append(fail(path, "resolved and interim records MUST share jobId"))
    return errors


def validate_pair(interim_path: Path, resolved_path: Path) -> list[str]:
    interim, errors = validate_interim(interim_path)
    errors += validate_resolved(resolved_path, interim)
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("interim", nargs="?", type=Path, default=DEFAULT_INTERIM)
    parser.add_argument("resolved", nargs="?", type=Path, default=DEFAULT_RESOLVED)
    args = parser.parse_args(argv)
    errors = validate_pair(args.interim, args.resolved)
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        return 1
    print("validated HTLC-9 ST-8 supersession pack: 2 fixture(s), both signatures verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
