#!/usr/bin/env python3
"""Strictly validate the committed offline adapter-runner acceptance packet."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
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
STANDARD_HEAD = "c799a163e80bff867ba01bc9e08f15ab7916e139"
DESCRIPTOR_PATH = "conformance/interop/dacs-adapter-release-proposal-v1.json"
DESCRIPTOR_SHA256 = "723d344e1487361c699cd0750a8567d7e2021cbbcbc1ff90efa39e8a423fecca"
PACKET_LIMITATIONS = [
    "Two runs wrap one DACS-Standard implementation; every scored result is SELF-CHECK.",
    "No independent cross-implementation, full legacy/default corpus, live system, or generic domain-separation claim.",
    "This packet is separate from dacs-cross-run-evidence/1, which does not execute or assess adapters.",
    "The offline validator checks recorded pins, coverage and internal consistency; the producer execution supplies the run evidence and does not certify a hostile host.",
]


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


def require_object(value, label):
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def require_array(value, label):
    require(isinstance(value, list), f"{label} must be an array")
    return value


def require_member_object(parent, key, label):
    return require_object(parent.get(key), label)


def require_member_array(parent, key, label):
    return require_array(parent.get(key), label)


def require_integer(value, label, *, minimum=0):
    require(type(value) is int and value >= minimum,
            f"{label} must be an integer >= {minimum}")
    return value


def require_keys(value, expected, label):
    require(set(value) == set(expected), f"{label} has missing or unrecognized members")


def descriptor_expectations():
    try:
        completed = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(ROOT), "show",
             f"{STANDARD_HEAD}:{DESCRIPTOR_PATH}"],
            capture_output=True, check=False, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PacketError("cannot read frozen descriptor from Git") from exc
    require(completed.returncode == 0,
            "frozen descriptor is unavailable in Git history")
    raw = completed.stdout
    require(hashlib.sha256(raw).hexdigest() ==
            DESCRIPTOR_SHA256,
            "frozen descriptor digest changed")
    descriptor = require_object(json.loads(raw), "frozen descriptor")
    descriptor_adapter = require_member_object(
        descriptor, "adapter", "frozen descriptor adapter"
    )
    wrapped = require_member_object(
        descriptor_adapter, "wrappedStandard",
        "frozen descriptor wrappedStandard",
    )
    require(set(wrapped) == {"revision", "tree", "primitives"},
            "frozen descriptor wrappedStandard members changed")
    primitives = require_member_array(
        wrapped, "primitives", "frozen descriptor wrappedStandard primitives"
    )
    primitive_sha256 = {}
    for index, primitive_value in enumerate(primitives):
        primitive = require_object(
            primitive_value,
            f"frozen descriptor wrappedStandard primitives[{index}]",
        )
        path_value = primitive.get("path")
        digest = primitive.get("sha256")
        require(isinstance(path_value, str) and path_value,
                f"frozen descriptor primitive {index} path must be a string")
        require(isinstance(digest, str) and len(digest) == 64,
                f"frozen descriptor primitive {path_value} digest is malformed")
        require(path_value not in primitive_sha256,
                f"frozen descriptor primitive {path_value} is duplicated")
        primitive_sha256[path_value] = digest
    expected_wrapped = {
        "revision": wrapped.get("revision"),
        "tree": wrapped.get("tree"),
        "primitiveSha256": primitive_sha256,
    }
    expected_adapter = {
        "name": descriptor_adapter.get("name"),
        "version": descriptor_adapter.get("version"),
        "repository": descriptor_adapter.get("repository"),
        "observedOrigin": "https://github.com/DACS-Agent-commerce/DACS-Standard.git",
        "revision": "sha256:" + descriptor_adapter["source"]["sha256"],
        "provenanceCodebase": "github.com/DACS-Agent-commerce/DACS-Standard",
        "supportedFamilies": [
            "canonical-accept", "canonical-reject", "drift-signed-scope",
            "sig-value-encoding",
        ],
        "operations": [
            "canonicalize", "signedScopeHash", "signatureValueVerdict",
            "domainSepSign", "domainSepVerify",
        ],
        "boundedOperationProfiles": {
            "domainSepSign": "listing-single-hash-golden-v1",
            "domainSepVerify": "listing-single-hash-golden-v1",
        },
        "wrappedStandard": expected_wrapped,
        "limitations": descriptor_adapter.get("limitations"),
    }
    families = require_member_array(
        descriptor, "families", "frozen descriptor families"
    )
    cases = {}
    for family_index, family_value in enumerate(families):
        family = require_object(
            family_value, f"frozen descriptor families[{family_index}]"
        )
        for case_index, case_value in enumerate(require_member_array(
            family, "cases", f"frozen descriptor families[{family_index}].cases"
        )):
            case = require_object(
                case_value,
                f"frozen descriptor families[{family_index}].cases[{case_index}]",
            )
            case_id = case.get("caseId")
            require(isinstance(case_id, str) and case_id not in cases,
                    "frozen descriptor case IDs must be unique strings")
            cases[case_id] = {
                "operation": case.get("operation", family.get("operation")),
                "outcome": (
                    f"ERROR-CODE:{case['expectedErrorCode']}"
                    if "expectedErrorCode" in case
                    else json.dumps(case["expected"], separators=(",", ":"))
                ),
            }
    return cases, expected_wrapped, expected_adapter


def validate(packet):
    require(isinstance(packet, dict) and packet.get("schema") == SCHEMA, "wrong packet schema")
    require(packet.get("accepted") is True, "packet is not accepted")
    coordinates = require_member_object(packet, "coordinates", "coordinates")
    standard = require_member_object(coordinates, "standard", "coordinates.standard")
    runner = require_member_object(coordinates, "runner", "coordinates.runner")
    adapter = require_member_object(packet, "adapter", "adapter")
    runtime = require_member_object(packet, "runtime", "runtime")
    limitations = require_member_array(packet, "limitations", "limitations")
    require(isinstance(adapter.get("name"), str) and adapter.get("name"),
            "adapter.name must be a non-empty string")
    require(standard.get("repository") == "https://github.com/DACS-Agent-commerce/DACS-Standard", "wrong Standard repository")
    require(standard.get("head") == STANDARD_HEAD, "wrong Standard head")
    require(standard.get("tree") == "2fadbac38d9013268b41dec47c1090d5ac9c5600", "wrong Standard tree")
    require(standard.get("descriptorSha256") == DESCRIPTOR_SHA256, "wrong descriptor digest")
    require(standard.get("wrappedStandard") == "ef69d46a81e3018b6eb9aa7cb25489657ed91def", "wrong wrapped Standard")
    require(standard.get("adapterSourceSha256") == "a29c0ffcbf3918df72dde80f37abb73358e9a635c05fb58aa1cac14c738b84a6", "wrong adapter source")
    require(runner.get("repository") == "https://github.com/cX3po/pathos-dacs-ref", "wrong runner repository")
    require(runner.get("baseHead") == "1297dd5f79d2e1305bfd4e8e4b2fa6830bc72eda", "wrong runner base")
    require(runner.get("patchSha256") == "178d58f2682a145810e6ec7611d3b348c502c2cd94917231e97360973bb6639d", "wrong runner patch")
    require(runner.get("issueComment") ==
            "https://github.com/DACS-Agent-commerce/DACS-Standard/issues/270#issuecomment-5696719263",
            "wrong runner issue comment")
    runner_sources = require_member_object(
        runner, "sourceSha256", "coordinates.runner.sourceSha256"
    )
    require(runner_sources == RUNNER_SOURCES, "runner source pins differ from reviewed bytes")
    expected_section = require_member_object(packet, "expected", "expected")
    expected_summary = require_member_object(
        expected_section, "summary", "expected.summary"
    )
    require_integer(expected_section.get("cases"), "expected.cases", minimum=1)
    for key in ("SELF-CHECK", "ABSTAIN", "INTEROP-AGREE", "ERROR"):
        require_integer(expected_summary.get(key), f"expected.summary.{key}")
    require(expected_section == {"cases": 20, "summary": {
        "SELF-CHECK": 18, "ABSTAIN": 2, "INTEROP-AGREE": 0, "ERROR": 0}}, "wrong independent expectations")
    observed = require_member_object(packet, "observed", "observed")
    matrix = require_member_array(observed, "matrix", "observed.matrix")
    require(len(matrix) == 20, "matrix must contain 20 cases")
    rows = []
    ids = []
    for index, row_value in enumerate(matrix):
        row = require_object(row_value, f"observed.matrix[{index}]")
        case_id = row.get("id")
        require(isinstance(case_id, str), f"observed.matrix[{index}].id must be a string")
        rows.append(row)
        ids.append(case_id)
    require(set(ids) == EXPECTED_IDS and len(set(ids)) == len(ids),
            "case set is incomplete or duplicated")
    expected_outcomes, expected_wrapped, expected_adapter = descriptor_expectations()
    for row in rows:
        case_id = row["id"]
        expected = expected_outcomes.get(case_id, {
            "bigint-native-type": {"operation": "canonicalize"},
            "signing::valid-raw-digest-profile-boundary": {"operation": "domainSepVerify"},
        }.get(case_id))
        require(isinstance(expected, dict), f"{case_id}: no frozen expectation")
        require(row.get("operation") == expected["operation"], f"{case_id}: wrong operation mapping")
        require_integer(row.get("participatingAdapters"),
                        f"{case_id}: participatingAdapters")
        require_integer(row.get("independentImplementations"),
                        f"{case_id}: independentImplementations")
        adapters = require_member_array(row, "adapters", f"{case_id}: adapters")
        require(len(adapters) == 2, f"{case_id}: adapters must contain two runs")
        adapter_rows = []
        run_ids = []
        for index, item_value in enumerate(adapters):
            item = require_object(item_value, f"{case_id}: adapters[{index}]")
            run_id = item.get("runId")
            require(isinstance(run_id, str),
                    f"{case_id}: adapters[{index}].runId must be a string")
            require(item.get("name") == adapter.get("name"),
                    f"{case_id}: adapter identity differs from packet metadata")
            adapter_rows.append(item)
            run_ids.append(run_id)
        if case_id in ABSTAIN_IDS:
            require(row.get("status") == "ABSTAIN" and row.get("participatingAdapters") == 0
                    and row.get("independentImplementations") == 0, f"{case_id}: must fully ABSTAIN")
            require(all(item.get("status") == "ABSTAIN"
                    and item.get("errorCode") == "UNSUPPORTED_CASE" and item.get("outcome") is None
                    for item in adapter_rows),
                    f"{case_id}: missing explicit unsupported evidence")
            require(set(run_ids) == {"run-0", "run-1"},
                    f"{case_id}: runner identities are incomplete")
        else:
            require(row.get("expected") == expected["outcome"],
                    f"{case_id}: expected value differs from frozen descriptor")
            require(row.get("status") == "SELF-CHECK" and row.get("participatingAdapters") == 2
                    and row.get("independentImplementations") == 1, f"{case_id}: false independence or result")
            require(all(item.get("status") == "matches-expected"
                    for item in adapter_rows), f"{case_id}: adapter result mismatch")
            require(all(item.get("outcome") == row.get("expected") for item in adapter_rows),
                    f"{case_id}: observed outcome differs from expected")
            require(set(run_ids) == {"run-0", "run-1"},
                    f"{case_id}: runner identities are incomplete")
    summary = require_member_object(observed, "summary", "observed.summary")
    for key in (
        "SELF-CHECK", "ABSTAIN", "INTEROP-AGREE", "ERROR",
        "VECTOR-MISMATCH", "IMPLEMENTATION-DIVERGENCE",
    ):
        require_integer(summary.get(key), f"observed.summary.{key}")
    require(summary.get("SELF-CHECK") == 18 and summary.get("ABSTAIN") == 2
            and all(summary.get(key) == 0 for key in ("INTEROP-AGREE", "ERROR", "VECTOR-MISMATCH", "IMPLEMENTATION-DIVERGENCE")),
            "observed summary is not 18 SELF-CHECK plus 2 ABSTAIN")
    mismatch = next(row for row in rows if row["id"] == "signing::reject-mismatched-ascii-hex-hash")
    require(mismatch.get("expected") == "false" and all(item.get("outcome") == "false" for item in mismatch["adapters"]),
            "in-profile cryptographic mismatch must return false")
    controls = require_member_object(packet, "controls", "controls")
    require(controls.get("rawDigestSignatureValidatedBeforeAdapter") is True, "missing raw-digest control")
    mismatch_control = require_member_object(
        controls, "inProfileCryptoMismatch", "controls.inProfileCryptoMismatch"
    )
    require_member_array(
        mismatch_control, "observed", "controls.inProfileCryptoMismatch.observed"
    )
    require(mismatch_control == {
        "id": mismatch["id"], "expected": False, "observed": [False, False]},
        "in-profile mismatch control contradicts matrix evidence")
    require(controls.get("exportedLaunchFailureProbe") == "ERROR"
            and controls.get("exportedMalformedProtocolProbe") == "ERROR",
            "launch and protocol failures must be ERROR")
    execution = require_member_object(packet, "execution", "execution")
    adapter_command = require_member_array(
        execution, "adapterCommand", "execution.adapterCommand"
    )
    require(adapter_command == ["python3", "scripts/dacs_adapter.py"], "non-portable adapter command")
    require(execution.get("adapterRuns") == 2, "packet must record two wrapper runs")
    require_integer(execution.get("adapterRuns"), "execution.adapterRuns", minimum=1)
    focused = require_member_object(
        execution, "contributorFocusedSuite", "execution.contributorFocusedSuite"
    )
    for key in ("passed", "failed", "skipped"):
        require_integer(focused.get(key), f"execution.contributorFocusedSuite.{key}")
    require(focused.get("passed") == 16
            and focused.get("failed") == 0
            and focused.get("skipped") == 0,
            "contributor focused suite result must be 16/16 with zero skips")
    focused_command = require_member_array(
        focused, "command", "execution.contributorFocusedSuite.command"
    )
    require(focused_command ==
            ["node", "--test", "conformance/shared-suite/unsupported-case.test.mjs"]
            and focused.get("canonicalTmpdirResolved") is True,
            "focused suite command or canonical temporary-path control is missing")
    python_runtime = require_member_object(runtime, "python", "runtime.python")
    require(runtime == {"node": "v24.19.0", "openssl": "3.5.7", "python": {
        "version": "3.12.6", "cryptography": "46.0.5", "idna": "3.10"}},
        "runtime versions differ from the executed packet")
    require(python_runtime == {
        "version": "3.12.6", "cryptography": "46.0.5", "idna": "3.10"
    }, "Python runtime versions differ from the executed packet")
    require(adapter.get("repository") == standard.get("repository")
            and adapter.get("provenanceCodebase") == "github.com/DACS-Agent-commerce/DACS-Standard",
            "adapter and implementation identity mapping changed")
    require(adapter.get("revision") == "sha256:a29c0ffcbf3918df72dde80f37abb73358e9a635c05fb58aa1cac14c738b84a6",
            "adapter metadata revision differs from source pin")
    packet_wrapped = require_member_object(
        adapter, "wrappedStandard", "adapter.wrappedStandard"
    )
    require(set(packet_wrapped) == {"revision", "tree", "primitiveSha256"},
            "adapter wrapped Standard metadata has missing or extra members")
    require_member_object(
        packet_wrapped, "primitiveSha256", "adapter.wrappedStandard.primitiveSha256"
    )
    require(packet_wrapped.get("revision") == expected_wrapped["revision"],
            "adapter metadata wrapped revision differs from descriptor pin")
    require(packet_wrapped == expected_wrapped,
            "adapter wrapped Standard metadata differs from frozen descriptor")
    require(packet_wrapped["revision"] == standard.get("wrappedStandard"),
            "adapter metadata wrapped revision differs from descriptor pin")
    require(adapter == expected_adapter,
            "adapter metadata differs from frozen descriptor and contract")
    require(limitations == PACKET_LIMITATIONS,
            "packet limitations differ from the recorded producer contract")
    # Schema /1 has no extension namespace: extra claim-bearing fields must not
    # be silently accepted as if the validator had checked them.
    for label, section, keys in (
        ("packet", packet, ("schema", "accepted", "coordinates", "runtime",
                            "execution", "adapter", "expected", "observed",
                            "controls", "limitations")),
        ("coordinates", coordinates, ("standard", "runner")),
        ("coordinates.standard", standard, ("repository", "head", "tree",
                                           "descriptorSha256", "adapterSourceSha256",
                                           "wrappedStandard")),
        ("coordinates.runner", runner, ("repository", "baseHead", "patchSha256",
                                       "issueComment", "sourceSha256")),
        ("observed", observed, ("summary", "matrix")),
        ("observed.summary", summary, ("SELF-CHECK", "ABSTAIN", "INTEROP-AGREE",
                                        "ERROR", "VECTOR-MISMATCH",
                                        "IMPLEMENTATION-DIVERGENCE")),
        ("controls", controls, ("rawDigestSignatureValidatedBeforeAdapter",
                                "inProfileCryptoMismatch", "exportedLaunchFailureProbe",
                                "exportedMalformedProtocolProbe")),
        ("execution", execution, ("adapterCommand", "adapterRuns",
                                  "contributorFocusedSuite")),
        ("execution.contributorFocusedSuite", focused,
         ("command", "canonicalTmpdirResolved", "passed", "failed", "skipped")),
    ):
        require_keys(section, keys, label)
    for row in rows:
        case_id = row["id"]
        row_keys = {"id", "operation", "status", "participatingAdapters",
                    "independentImplementations", "adapters"}
        if case_id not in ABSTAIN_IDS:
            row_keys.add("expected")
        require_keys(row, row_keys, f"{case_id}: observed row")
        for item in row["adapters"]:
            adapter_keys = {"runId", "name", "status", "outcome"}
            if case_id in ABSTAIN_IDS:
                adapter_keys.add("errorCode")
            require_keys(item, adapter_keys, f"{case_id}: adapter row")
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
