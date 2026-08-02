#!/usr/bin/env python3
"""Validate provisional DACS-X dispute interface pack fixtures."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DISPUTE_FIXTURE = ROOT / "conformance" / "fixtures" / "dacsx" / "dispute-outcome-htlc9-correction.json"
DEFAULT_HTLC9_FIXTURE = ROOT / "conformance" / "fixtures" / "settlement" / "htlc9-asymmetric.json"


def fail(path: Path, message: str) -> str:
    try:
        label = path.resolve().relative_to(ROOT)
    except ValueError:
        label = path
    return f"{label}: {message}"


def is_attestation_ref(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("kind"), str)
        and isinstance(value.get("locator"), str)
        and isinstance(value.get("contentHash"), str)
        and value["contentHash"].startswith("sha256:")
        and len(value["contentHash"].removeprefix("sha256:")) == 64
    )


def validate_htlc9_evidence_case(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [fail(path, "fixture file not found")]
    except json.JSONDecodeError as exc:
        return [fail(path, f"invalid JSON: {exc}")]

    if data.get("kind") != "SettlementEvidenceCase":
        errors.append(fail(path, "kind MUST be SettlementEvidenceCase"))
    evidence = data.get("settlementEvidence")
    if not isinstance(evidence, dict):
        return errors + [fail(path, "settlementEvidence MUST be an object")]
    if evidence.get("evidenceVersion") != "1":
        errors.append(fail(path, "evidenceVersion MUST be '1'"))
    if evidence.get("phase") != "pay-cross-chain-htlc":
        errors.append(fail(path, "phase MUST be pay-cross-chain-htlc"))
    if evidence.get("outcome") != "failure":
        errors.append(fail(path, "HTLC-9 interim evidence MUST have outcome failure"))
    if evidence.get("reason") != "dest-revealed-source-unclaimed":
        errors.append(fail(path, "HTLC-9 interim evidence MUST carry dest-revealed-source-unclaimed reason"))
    tx_refs = evidence.get("paymentTxRefs")
    if not isinstance(tx_refs, list) or not tx_refs:
        errors.append(fail(path, "paymentTxRefs MUST be a non-empty array"))
    elif not any(ref.get("kind") == "htlc-reveal" for ref in tx_refs if isinstance(ref, dict)):
        errors.append(fail(path, "paymentTxRefs MUST include an htlc-reveal txRef proving preimage disclosure"))
    if "settlementFinality" in evidence:
        errors.append(fail(path, "HTLC-9 interim failure evidence MUST NOT carry settlementFinality"))
    return errors


def validate_dispute_outcome_case(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [fail(path, "fixture file not found")]
    except json.JSONDecodeError as exc:
        return [fail(path, f"invalid JSON: {exc}")]

    if data.get("kind") != "DisputeOutcomeCase":
        errors.append(fail(path, "kind MUST be DisputeOutcomeCase"))
    outcome = data.get("disputeOutcome")
    if not isinstance(outcome, dict):
        return errors + [fail(path, "disputeOutcome MUST be an object")]
    required = {
        "outcomeVersion",
        "jobId",
        "disputeKind",
        "subjectBundleRefs",
        "subjectEvidenceRef",
        "decision",
        "rationale",
        "signature",
    }
    missing = sorted(required - set(outcome))
    if missing:
        errors.append(fail(path, "disputeOutcome missing keys: " + ", ".join(missing)))
    if outcome.get("outcomeVersion") != "1":
        errors.append(fail(path, "outcomeVersion MUST be '1'"))
    if outcome.get("disputeKind") != "htlc9-asymmetric-settlement":
        errors.append(fail(path, "disputeKind MUST be htlc9-asymmetric-settlement for this pack"))
    refs = outcome.get("subjectBundleRefs")
    if not isinstance(refs, list) or len(refs) < 1 or not all(is_attestation_ref(ref) for ref in refs):
        errors.append(fail(path, "subjectBundleRefs MUST contain AttestationRef objects"))
    if not is_attestation_ref(outcome.get("subjectEvidenceRef")):
        errors.append(fail(path, "subjectEvidenceRef MUST be an AttestationRef"))
    amendment = outcome.get("settlementAmendment")
    if not isinstance(amendment, dict):
        errors.append(fail(path, "settlementAmendment MUST be present for HTLC-9 correction cases"))
    else:
        if amendment.get("jobId") != outcome.get("jobId"):
            errors.append(fail(path, "settlementAmendment.jobId MUST match disputeOutcome.jobId"))
        if amendment.get("amendmentType") != "correction":
            errors.append(fail(path, "HTLC-9 dispute close-out MUST use amendmentType correction"))
        if "refundAmount" in amendment:
            errors.append(fail(path, "correction amendments MUST NOT carry refundAmount"))
        if amendment.get("reason") != "dacsx-htlc9-source-claim-confirmed":
            errors.append(fail(path, "HTLC-9 correction reason MUST be dacsx-htlc9-source-claim-confirmed"))
        if not is_attestation_ref(amendment.get("amendsEvidenceRef")):
            errors.append(fail(path, "amendsEvidenceRef MUST be an AttestationRef"))
    return errors


def validate_path(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [fail(path, "fixture file not found")]
    except json.JSONDecodeError as exc:
        return [fail(path, f"invalid JSON: {exc}")]
    kind = data.get("kind")
    if kind == "DisputeOutcomeCase":
        return validate_dispute_outcome_case(path)
    if kind == "SettlementEvidenceCase":
        return validate_htlc9_evidence_case(path)
    return [fail(path, f"unsupported fixture kind: {kind!r}")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate provisional DACS-X dispute fixtures")
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args(argv)
    paths = args.paths or [DEFAULT_HTLC9_FIXTURE, DEFAULT_DISPUTE_FIXTURE]
    all_errors: list[str] = []
    for path in paths:
        all_errors.extend(validate_path(path))
    if all_errors:
        print("DACS-X dispute pack validation failed:", file=sys.stderr)
        for error in all_errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"validated DACS-X dispute pack: {len(paths)} fixture(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
