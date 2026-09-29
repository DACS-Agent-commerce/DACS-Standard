#!/usr/bin/env python3
"""Strictly validate the committed offline adapter-runner acceptance packet."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "conformance/interop/runner-acceptance-v1.json"
SCHEMA = "dacs-adapter-runner-acceptance/1"
EXPECTED_IDS = {
    "fraction-one-half", "fraction-one-e-minus-seven", "maximum-dacs-magnitude",
    "nfd-string-value-normalizes-to-nfc", "member-name-order-is-utf16",
    "number-over-dacs-magnitude", "settlement-htlc-release", "attestation-bundle-happy",
    "canonical-base64url-unpadded", "standard-base64-same-bytes-rejected",
    "padded-base64url-same-bytes-rejected", "embedded-whitespace-rejected",
    "impossible-length-rejected", "non-zero-residual-bits-rejected",
    "signing::sign-ascii-hex-hash", "signing::verify-ascii-hex-hash",
    "signing::reject-mismatched-ascii-hex-hash", "signing::unknown-separator-false",
    "bigint-native-type", "signing::valid-raw-digest-profile-boundary",
}
ABSTAIN_IDS = {"bigint-native-type", "signing::valid-raw-digest-profile-boundary"}
RUNNER_SOURCES = {
    "conformance/shared-suite/standard-405-pilot.mjs": "0374fda135a9b564caabaaa73d16988911e44dccb88e433c9c928c449c71b431",
    "conformance/shared-suite/adapter-contract.mjs": "0fb13bc47e0cf4ad068a422caa9c8ed73085a3f135c17ccd851ad412130deba9",
    "conformance/shared-suite/adapter-process-client.mjs": "17c268e72b82e639e7c053f564ce13fd10d00e84add35984aae24bf4238990c0",
    "conformance/shared-suite/adapter-registry.mjs": "db42abb3177fe1ad3aeb113f19fdaef0fadaf212895a4e412e7569762259923b",
    "conformance/shared-suite/unsupported-case.test.mjs": "a0416d52c4206564fa00bff2f7998c6de9e66f377ecb8a8d34ed6b8219cbb6ea",
    "conformance/shared-suite/cross-run.mjs": "56dd845387ec90a8e400613517e57a16b3e2f585eee2c1bb24b1c44b458b0ee2",
}


class PacketError(ValueError):
    pass


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PacketError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(PacketError(f"non-finite {value}")))


def require(condition, message):
    if not condition:
        raise PacketError(message)


def descriptor_expectations():
    path = ROOT / "conformance/interop/frozen/dacs-adapter-release-proposal-c799-v1.json"
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() ==
            "723d344e1487361c699cd0750a8567d7e2021cbbcbc1ff90efa39e8a423fecca",
            "local frozen descriptor digest changed")
    descriptor = json.loads(raw)
    return {case["caseId"]: {
        "operation": case.get("operation", family.get("operation")),
        "outcome": (f"ERROR-CODE:{case['expectedErrorCode']}" if "expectedErrorCode" in case
                    else json.dumps(case["expected"], separators=(",", ":"))),
    } for family in descriptor["families"] for case in family["cases"]}


def validate(packet):
    require(isinstance(packet, dict) and packet.get("schema") == SCHEMA, "wrong packet schema")
    require(packet.get("accepted") is True, "packet is not accepted")
    coordinates = packet.get("coordinates", {})
    standard, runner = coordinates.get("standard", {}), coordinates.get("runner", {})
    require(standard.get("repository") == "https://github.com/DACS-Agent-commerce/DACS-Standard", "wrong Standard repository")
    require(standard.get("head") == "c799a163e80bff867ba01bc9e08f15ab7916e139", "wrong Standard head")
    require(standard.get("tree") == "2fadbac38d9013268b41dec47c1090d5ac9c5600", "wrong Standard tree")
    require(standard.get("descriptorSha256") == "723d344e1487361c699cd0750a8567d7e2021cbbcbc1ff90efa39e8a423fecca", "wrong descriptor digest")
    require(standard.get("wrappedStandard") == "ef69d46a81e3018b6eb9aa7cb25489657ed91def", "wrong wrapped Standard")
    require(standard.get("adapterSourceSha256") == "a29c0ffcbf3918df72dde80f37abb73358e9a635c05fb58aa1cac14c738b84a6", "wrong adapter source")
    require(runner.get("repository") == "https://github.com/cX3po/pathos-dacs-ref", "wrong runner repository")
    require(runner.get("baseHead") == "1297dd5f79d2e1305bfd4e8e4b2fa6830bc72eda", "wrong runner base")
    require(runner.get("patchSha256") == "178d58f2682a145810e6ec7611d3b348c502c2cd94917231e97360973bb6639d", "wrong runner patch")
    require(runner.get("issueComment") ==
            "https://github.com/DACS-Agent-commerce/DACS-Standard/issues/270#issuecomment-5696719263",
            "wrong runner issue comment")
    require(runner.get("sourceSha256") == RUNNER_SOURCES, "runner source pins differ from reviewed bytes")
    require(packet.get("expected") == {"cases": 20, "summary": {
        "SELF-CHECK": 18, "ABSTAIN": 2, "INTEROP-AGREE": 0, "ERROR": 0}}, "wrong independent expectations")
    observed = packet.get("observed", {})
    matrix = observed.get("matrix")
    require(isinstance(matrix, list) and len(matrix) == 20, "matrix must contain 20 cases")
    require({row.get("id") for row in matrix if isinstance(row, dict)} == EXPECTED_IDS, "case set is incomplete or duplicated")
    expected_outcomes = descriptor_expectations()
    for row in matrix:
        case_id = row["id"]
        expected = expected_outcomes.get(case_id, {
            "bigint-native-type": {"operation": "canonicalize"},
            "signing::valid-raw-digest-profile-boundary": {"operation": "domainSepVerify"},
        }.get(case_id))
        require(row.get("operation") == expected["operation"], f"{case_id}: wrong operation mapping")
        if case_id in ABSTAIN_IDS:
            require(row.get("status") == "ABSTAIN" and row.get("participatingAdapters") == 0
                    and row.get("independentImplementations") == 0, f"{case_id}: must fully ABSTAIN")
            require(len(row.get("adapters", [])) == 2 and all(item.get("status") == "ABSTAIN"
                    and item.get("errorCode") == "UNSUPPORTED_CASE" and item.get("outcome") is None
                    for item in row["adapters"]),
                    f"{case_id}: missing explicit unsupported evidence")
            require({item.get("runId") for item in row["adapters"]} == {"run-0", "run-1"},
                    f"{case_id}: runner identities are incomplete")
        else:
            require(row.get("expected") == expected["outcome"],
                    f"{case_id}: expected value differs from frozen descriptor")
            require(row.get("status") == "SELF-CHECK" and row.get("participatingAdapters") == 2
                    and row.get("independentImplementations") == 1, f"{case_id}: false independence or result")
            require(len(row.get("adapters", [])) == 2 and all(item.get("status") == "matches-expected"
                    for item in row["adapters"]), f"{case_id}: adapter result mismatch")
            require(all(item.get("outcome") == row.get("expected") for item in row["adapters"]),
                    f"{case_id}: observed outcome differs from expected")
            require({item.get("runId") for item in row["adapters"]} == {"run-0", "run-1"},
                    f"{case_id}: runner identities are incomplete")
    summary = observed.get("summary", {})
    require(summary.get("SELF-CHECK") == 18 and summary.get("ABSTAIN") == 2
            and all(summary.get(key) == 0 for key in ("INTEROP-AGREE", "ERROR", "VECTOR-MISMATCH", "IMPLEMENTATION-DIVERGENCE")),
            "observed summary is not 18 SELF-CHECK plus 2 ABSTAIN")
    mismatch = next(row for row in matrix if row["id"] == "signing::reject-mismatched-ascii-hex-hash")
    require(mismatch.get("expected") == "false" and all(item.get("outcome") == "false" for item in mismatch["adapters"]),
            "in-profile cryptographic mismatch must return false")
    controls = packet.get("controls", {})
    require(controls.get("rawDigestSignatureValidatedBeforeAdapter") is True, "missing raw-digest control")
    require(controls.get("inProfileCryptoMismatch") == {
        "id": mismatch["id"], "expected": False, "observed": [False, False]},
        "in-profile mismatch control contradicts matrix evidence")
    require(controls.get("exportedLaunchFailureProbe") == "ERROR"
            and controls.get("exportedMalformedProtocolProbe") == "ERROR",
            "launch and protocol failures must be ERROR")
    execution = packet.get("execution", {})
    require(execution.get("adapterCommand") == ["python3", "scripts/dacs_adapter.py"], "non-portable adapter command")
    require(execution.get("adapterRuns") == 2, "packet must record two wrapper runs")
    require(execution.get("contributorFocusedSuite", {}).get("passed") == 16
            and execution["contributorFocusedSuite"].get("failed") == 0
            and execution["contributorFocusedSuite"].get("skipped") == 0,
            "contributor focused suite result must be 16/16 with zero skips")
    require(execution["contributorFocusedSuite"].get("command") ==
            ["node", "--test", "conformance/shared-suite/unsupported-case.test.mjs"]
            and execution["contributorFocusedSuite"].get("canonicalTmpdirResolved") is True,
            "focused suite command or canonical temporary-path control is missing")
    adapter = packet.get("adapter", {})
    require(packet.get("runtime") == {"node": "v24.19.0", "openssl": "3.5.7", "python": {
        "version": "3.12.6", "cryptography": "46.0.5", "idna": "3.10"}},
        "runtime versions differ from the executed packet")
    require(adapter.get("repository") == standard.get("repository")
            and adapter.get("provenanceCodebase") == "github.com/DACS-Agent-commerce/DACS-Standard",
            "adapter and implementation identity mapping changed")
    require(adapter.get("revision") == "sha256:a29c0ffcbf3918df72dde80f37abb73358e9a635c05fb58aa1cac14c738b84a6",
            "adapter metadata revision differs from source pin")
    require(adapter.get("wrappedStandard", {}).get("revision") == standard.get("wrappedStandard"),
            "adapter metadata wrapped revision differs from descriptor pin")
    return packet


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", nargs="?", type=Path, default=PACKET)
    args = parser.parse_args(argv)
    try:
        packet = validate(load(args.packet))
    except (OSError, json.JSONDecodeError, PacketError, KeyError, StopIteration) as exc:
        print(f"adapter runner acceptance: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"adapter runner acceptance: PASS ({len(packet['observed']['matrix'])} cases; 18 SELF-CHECK, 2 ABSTAIN)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
