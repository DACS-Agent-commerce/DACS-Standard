#!/usr/bin/env python3
"""Measure fixture-only #392 D2 local elapsed time and model acquisition timing."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import math
import platform
import statistics
import subprocess
import sys
import time
from importlib.metadata import version
from pathlib import Path

try:
    from scripts.finality_resolution_context_reference import (
        FinalityResolutionAuthority,
    )
    from scripts.settlement_finality_reference import verify_finality
except ImportError:
    from finality_resolution_context_reference import FinalityResolutionAuthority
    from settlement_finality_reference import verify_finality


ROOT = Path(__file__).resolve().parents[1]
VECTOR = (
    ROOT / "conformance" / "vectors" / "security"
    / "finality-resolution-context-v1.json"
)
MODELED_RESPONSE_DELAYS_MS = (120, 410)


def command(*args: str) -> str:
    return subprocess.run(
        args,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def authority_from_fixture(data: dict) -> FinalityResolutionAuthority:
    payload = copy.deepcopy(data["positive"]["authority"])
    return FinalityResolutionAuthority(
        authenticated=payload["authenticated"],
        policy=payload["policy"],
        issued_query=payload["issuedQuery"],
        checkpoint_source=payload["checkpointSource"],
        policy_source=payload["policySource"],
        authority_set_source=payload["authoritySetSource"],
        base_trusted=copy.deepcopy(data["baseTrusted"]),
        verification_time_ms=payload["verificationTimeMs"],
        acquisition_records=tuple(payload["acquisitionRecords"]),
        retained_responses=tuple(payload["retainedResponses"]),
    )


def percentile_nearest_rank(samples: list[int], percentile: float) -> int:
    ordered = sorted(samples)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def measure(warmup: int, samples: int) -> dict:
    # Loading, trust construction, fixture generation and signing are deliberately
    # outside the timed region. The verifier receives the same immutable fixture
    # and verifier-owned authority object for each sample.
    raw = VECTOR.read_bytes()
    data = json.loads(raw)
    value = data["positive"]["value"]
    trusted = copy.deepcopy(data["baseTrusted"])
    trusted["finalityResolutionAuthority"] = authority_from_fixture(data)

    for _ in range(warmup):
        result = verify_finality(value, trusted)
        if result.get("decision") != "pass":
            raise RuntimeError("warm-up verification did not pass: " + repr(result))

    durations: list[int] = []
    for _ in range(samples):
        started = time.perf_counter_ns()
        result = verify_finality(value, trusted)
        ended = time.perf_counter_ns()
        if result.get("decision") != "pass":
            raise RuntimeError("measured verification did not pass: " + repr(result))
        durations.append(ended - started)

    head = command("git", "rev-parse", "HEAD")
    dirty = bool(command("git", "status", "--porcelain"))
    query = value["context"]["query"]
    acquisition_window_ms = (
        query["acquisitionBoundary"]["expiresAt"]
        - query["acquisitionBoundary"]["issuedAt"]
    )
    authority_count = data["authorityCount"]
    if authority_count != len(MODELED_RESPONSE_DELAYS_MS):
        raise RuntimeError("modeled delays do not match the registered fixture seats")

    return {
        "schemaVersion": "1",
        "measurement": {
            "clock": "time.perf_counter_ns",
            "scope": "verify_finality only; excludes JSON load, fixture generation, signing, and trust setup",
            "warmupCount": warmup,
            "sampleCount": samples,
            "medianNs": int(statistics.median(durations)),
            "p95NearestRankNs": percentile_nearest_rank(durations, 0.95),
            "minimumNs": min(durations),
            "maximumNs": max(durations),
            "decision": "pass",
        },
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "cryptography": version("cryptography"),
            "idna": version("idna"),
        },
        "source": {
            "commit": head,
            "worktreeDirty": dirty,
            "commitQualifiesExactCandidate": not dirty,
            "fixture": str(VECTOR.relative_to(ROOT)),
            "fixtureSha256": hashlib.sha256(raw).hexdigest(),
            "bindingCodec": query["binding"]["codec"],
            "bindingCodecVersion": query["binding"]["codecVersion"],
            "authorityCount": authority_count,
            "policyId": query["resolutionPolicy"]["policyId"],
            "policyVersion": query["resolutionPolicy"]["policyVersion"],
        },
        "modeledAcquisition": {
            "kind": "illustrative fixed-delay model; no transport was executed",
            "requiredAuthorityCount": authority_count,
            "sampleResponseDelaysMs": list(MODELED_RESPONSE_DELAYS_MS),
            "sequentialSumMs": sum(MODELED_RESPONSE_DELAYS_MS),
            "parallelSlowestSeatLowerBoundMs": max(MODELED_RESPONSE_DELAYS_MS),
            "missingSeatDeadlineMsFromIssue": acquisition_window_ms,
            "completeCoverageRequired": True,
            "missingSeatDecision": "indeterminate",
            "explicitUnavailableDecision": "indeterminate",
        },
        "thresholds": {
            "conformanceLatencyThreshold": None,
            "productionSla": None,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.warmup < 0 or args.samples <= 0:
        parser.error("--warmup must be non-negative and --samples must be positive")
    report = measure(args.warmup, args.samples)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
