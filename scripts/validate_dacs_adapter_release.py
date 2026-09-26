#!/usr/bin/env python3
"""Validate the non-normative issue-270 adapter release proposal."""

from __future__ import annotations

import os
import sys

if __name__ == "__main__":
    # Keep this checkout off the import path so an untracked file in it cannot
    # shadow a standard-library module imported below.
    _CHECKOUT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    sys.path[:] = [
        entry
        for entry in sys.path
        if os.path.realpath(entry or os.curdir) != _CHECKOUT
        and not os.path.realpath(entry or os.curdir).startswith(_CHECKOUT + os.sep)
    ]

import argparse
import ast
import base64
import hashlib
import json
import re
import subprocess
import types
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DESCRIPTOR = (
    ROOT / "conformance" / "interop" / "dacs-adapter-release-proposal-v1.json"
)
EXPECTED_ORIGIN = "https://github.com/DACS-Agent-commerce/DACS-Standard.git"
ADAPTER_SOURCE = "scripts/dacs_adapter.py"
BOUNDED_F5_SEPARATOR = "dacs-listing:v1:"
DACS_SEPARATOR_SHAPE = re.compile(r"dacs[-a-z0-9]*:v[0-9]+:")
PROTOCOL_TAGS = {"bytes", "bigint"}
FAMILY_STATUS = {
    "canonicalization": "executable",
    "signed-scope": "executable",
    "sig6-wire": "executable",
    "domain-separated-signing": "bounded-operation-profile",
}
GIT_REPOSITORY_ENV = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
}


def _git_run(*args: str) -> subprocess.CompletedProcess:
    environment = {key: value for key, value in os.environ.items() if key not in GIT_REPOSITORY_ENV}
    environment["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        env=environment,
    )


def _git(*args: str) -> str:
    return _git_run(*args).stdout.decode("utf-8").strip()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def _load_bytes_at_revision(source: dict[str, Any]) -> bytes:
    path = source["path"]
    revision = source["revision"]
    blob = _git("rev-parse", f"{revision}:{path}")
    if blob != source["gitBlob"]:
        raise ValueError(f"{path}: git blob does not match descriptor")
    data = _git_run("show", f"{revision}:{path}").stdout
    if _sha256(data) != source["sha256"]:
        raise ValueError(f"{path}: sha256 does not match descriptor")
    current = (ROOT / path).read_bytes()
    if current != data:
        raise ValueError(f"{path}: working file differs from the pinned source revision")
    return data


def _load_json_at_revision(source: dict[str, Any]) -> dict[str, Any]:
    return json.loads(_load_bytes_at_revision(source))


def _case_by_name(vectors: list[dict[str, Any]], case_id: str) -> dict[str, Any]:
    matches = [case for case in vectors if case.get("name") == case_id]
    if len(matches) != 1:
        raise ValueError(f"case {case_id!r}: expected one source match, got {len(matches)}")
    return matches[0]


def _artifact_by_id(artifacts: list[dict[str, Any]], case_id: str) -> dict[str, Any]:
    matches = [case for case in artifacts if case.get("id") == case_id]
    if len(matches) != 1:
        raise ValueError(f"case {case_id!r}: expected one source match, got {len(matches)}")
    return matches[0]


def _tags(value: Any) -> set[str]:
    """Every ``$dacsType`` tag name appearing anywhere in a source input."""

    found: set[str] = set()
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if "$dacsType" in item:
                found.add(str(item["$dacsType"]))
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return found


def _adapter_constants() -> dict[str, Any]:
    """The wrapped release fixed in the adapter source, read without running it."""

    wanted = {"WRAPPED_REVISION", "WRAPPED_TREE", "WRAPPED_MODULES"}
    found: dict[str, Any] = {}
    for node in ast.parse((ROOT / ADAPTER_SOURCE).read_bytes()).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in wanted:
                    found[target.id] = ast.literal_eval(node.value)
    if set(found) != wanted:
        raise ValueError("adapter source does not declare its wrapped Standard release")
    return found


def _bounded_text(value: Any, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit


def _load_verified_module(relative: str, expected_sha256: str, name: str) -> types.ModuleType:
    """Execute exactly the pinned bytes; never a re-read file or cached bytecode."""

    path = ROOT / relative
    data = path.read_bytes()
    if _sha256(data) != expected_sha256:
        raise ValueError(f"wrapped primitive sha256 mismatch: {relative}")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def _load_primitives(primitives: dict[str, str]) -> dict[str, types.ModuleType]:
    """Load the wrapped modules from verified bytes, resolving their local imports to them."""

    names = {"jcs": "scripts/jcs.py", "specsource": "scripts/specsource.py"}
    previous = {name: sys.modules.get(name) for name in names}
    loaded = {name: _load_verified_module(relative, primitives[relative], name) for name, relative in names.items()}
    sys.modules.update(loaded)  # ``import jcs`` / ``import specsource`` must see the verified modules
    try:
        loaded["walkthrough"] = _load_verified_module(
            "scripts/run_lifecycle_walkthrough.py",
            primitives["scripts/run_lifecycle_walkthrough.py"],
            "dacs_release_walkthrough",
        )
        loaded["vectors"] = _load_verified_module(
            "scripts/validate_conformance_vectors.py",
            primitives["scripts/validate_conformance_vectors.py"],
            "dacs_release_vectors",
        )
    finally:
        for name, module in previous.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module
    return loaded


def _validate_control_lines(control: dict[str, Any], data: bytes) -> None:
    match = re.fullmatch(r"([1-9][0-9]*)-([1-9][0-9]*)", str(control.get("lines", "")))
    test_name = control.get("test")
    if match is None or not isinstance(test_name, str):
        raise ValueError("bounded F5 control source must name its test and line range")
    start, end = int(match.group(1)), int(match.group(2))
    lines = data.decode("utf-8").splitlines()
    definition = f"    def {test_name}(self):"
    if start > end or end > len(lines) or lines[start - 1] != definition:
        raise ValueError("bounded F5 control line range does not start at the named test")
    body_end = start
    for number in range(start + 1, len(lines) + 1):
        text = lines[number - 1]
        if text.strip() and not text.startswith("        "):
            break
        if text.strip():
            body_end = number
    if end != body_end:
        raise ValueError("bounded F5 control line range does not cover exactly the named test")


def validate(descriptor_path: Path = DEFAULT_DESCRIPTOR) -> dict[str, int]:
    if not descriptor_path.is_file():
        raise ValueError("release descriptor is not a regular file")
    descriptor_bytes = descriptor_path.read_bytes()
    descriptor = json.loads(descriptor_bytes)
    observed_origin = _git("config", "--local", "--get", "remote.origin.url")
    if observed_origin not in {EXPECTED_ORIGIN, EXPECTED_ORIGIN.removesuffix(".git")}:
        raise ValueError("working repository origin is not the pinned DACS-Standard origin")
    descriptor_relative = descriptor_path.relative_to(ROOT).as_posix()
    if _git_blob_id(descriptor_bytes) != _git("rev-parse", f"HEAD:{descriptor_relative}"):
        raise ValueError("release descriptor is not committed at HEAD")
    source = descriptor.get("adapter", {}).get("source", {})
    if _git("rev-parse", f"HEAD:{ADAPTER_SOURCE}") != source.get("gitBlob"):
        raise ValueError("adapter source is not the pinned committed blob at HEAD")
    return validate_release(descriptor)


def validate_release(descriptor: dict[str, Any]) -> dict[str, int]:
    """Check descriptor content against the working tree and its pinned revisions."""

    if descriptor.get("schema") != "dacs-adapter-release-proposal/1":
        raise ValueError("unexpected descriptor schema")
    if descriptor.get("status") != "proposal-non-normative":
        raise ValueError("descriptor must remain explicitly non-normative")
    if descriptor.get("protocol", {}).get("id") != "dacs-adapter/1":
        raise ValueError("unexpected adapter protocol")
    repository = EXPECTED_ORIGIN.removesuffix(".git")
    if descriptor.get("adapter", {}).get("repository") != repository:
        raise ValueError("adapter repository identity is not DACS-Standard")
    if descriptor["adapter"].get("provenanceCodebase") != repository.removeprefix("https://"):
        raise ValueError("adapter codebase identity must be the revision-free DACS-Standard codebase")

    adapter = descriptor["adapter"]
    limitations = adapter.get("limitations")
    if not (
        _bounded_text(adapter.get("name"), 128)
        and _bounded_text(adapter.get("version"), 128)
        and isinstance(limitations, list)
        and 0 < len(limitations) <= 32
        and all(_bounded_text(item, 512) for item in limitations)
    ):
        raise ValueError("adapter name, version, or limitations are malformed")
    source = adapter["source"]
    if source.get("path") != ADAPTER_SOURCE:
        raise ValueError("adapter source pin must name the adapter itself")
    source_bytes = (ROOT / ADAPTER_SOURCE).read_bytes()
    if _sha256(source_bytes) != source["sha256"]:
        raise ValueError("adapter source sha256 does not match descriptor")
    if _git_blob_id(source_bytes) != source["gitBlob"]:
        raise ValueError("adapter source git blob does not match descriptor")

    wrapped = adapter["wrappedStandard"]
    constants = _adapter_constants()
    if wrapped["revision"] != constants["WRAPPED_REVISION"] or wrapped["tree"] != constants["WRAPPED_TREE"]:
        raise ValueError("wrapped Standard release differs from the one fixed in the adapter")
    if _git("rev-parse", f"{wrapped['revision']}^{{commit}}") != wrapped["revision"]:
        raise ValueError("wrapped Standard revision does not resolve to its pinned commit")
    if _git("rev-parse", f"{wrapped['revision']}^{{tree}}") != wrapped["tree"]:
        raise ValueError("wrapped Standard tree mismatch")
    expected_primitives = {relative: digest for _, relative, digest in constants["WRAPPED_MODULES"]}
    pinned = {primitive["path"]: primitive["sha256"] for primitive in wrapped["primitives"]}
    if len(wrapped["primitives"]) != len(expected_primitives) or pinned != expected_primitives:
        raise ValueError("wrapped primitive pins do not match the modules the adapter executes")
    for primitive in wrapped["primitives"]:
        path = primitive["path"]
        current = (ROOT / path).read_bytes()
        if _sha256(current) != primitive["sha256"]:
            raise ValueError(f"wrapped primitive sha256 mismatch: {path}")
        if _git_blob_id(current) != primitive["gitBlob"]:
            raise ValueError(f"wrapped primitive working blob mismatch: {path}")
        if _git("rev-parse", f"{wrapped['revision']}:{path}") != primitive["gitBlob"]:
            raise ValueError(f"wrapped primitive revision blob mismatch: {path}")
    primitive_sha256 = {primitive["path"]: primitive["sha256"] for primitive in wrapped["primitives"]}

    sources = {
        name: _load_json_at_revision(value)
        for name, value in descriptor["sources"].items()
    }
    executable = 0
    bounded = 0
    unsupported = 0
    modules = _load_primitives(primitive_sha256)
    family_ids = [family["id"] for family in descriptor["families"]]
    if sorted(family_ids) != sorted(FAMILY_STATUS):
        raise ValueError("release families differ from the proposal's four families")
    for family in descriptor["families"]:
        status = family["status"]
        if status != FAMILY_STATUS[family["id"]]:
            raise ValueError(f"family {family['id']}: invalid status {status!r}")
        case_ids = [
            item["caseId"]
            for key in ("cases", "unsupportedSourceCases", "excludedSourceCases", "primitiveControls", "unsupportedCases")
            for item in family.get(key, [])
        ]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError(f"family {family['id']}: duplicate case identifiers")
        if status == "bounded-operation-profile":
            bounded += len(family["cases"])
        else:
            executable += len(family["cases"])

        if family["id"] == "canonicalization":
            raw = sources[family["source"]]
            for selected in family["cases"]:
                actual = _case_by_name(raw["vectors"], selected["caseId"])
                if _tags(actual["input"]):
                    raise ValueError(f"{selected['caseId']}: selected input uses a tag dacs-adapter/1 cannot carry")
                if actual["expected"] != selected["sourceExpected"]:
                    raise ValueError(f"{selected['caseId']}: canonical source verdict drift")
                if actual["expected"] == "pass":
                    if "expectedErrorCode" in selected or actual["canonicalUtf8Hex"] != selected["expected"]["hex"]:
                        raise ValueError(f"{selected['caseId']}: canonical bytes drift")
                elif (
                    actual["expectedErrorCode"] != selected["sourceExpectedErrorCode"]
                    or "expected" in selected
                    or selected.get("expectedErrorCode") != "OPERATION_FAILED"
                ):
                    raise ValueError(f"{selected['caseId']}: canonical source error drift")
            for selected in family["unsupportedSourceCases"]:
                actual = _case_by_name(raw["vectors"], selected["caseId"])
                if actual["expected"] != selected["sourceExpected"]:
                    raise ValueError(f"{selected['caseId']}: unsupported source verdict drift")
                if actual["expectedErrorCode"] != selected["sourceExpectedErrorCode"]:
                    raise ValueError(f"{selected['caseId']}: unsupported source error drift")
                if selected["adapterErrorCode"] != "UNSUPPORTED_CASE":
                    raise ValueError(f"{selected['caseId']}: unsupported adapter boundary drift")
                unsupported += 1
            partition = [
                item["caseId"]
                for key in ("cases", "unsupportedSourceCases", "excludedSourceCases")
                for item in family[key]
            ]
            if len(partition) != len(set(partition)) or set(partition) != {
                item["name"] for item in raw["vectors"]
            }:
                raise ValueError(
                    "canonicalization selections, unsupported cases, and exclusions do not partition the source cases"
                )
            for excluded in family["excludedSourceCases"]:
                tags = _tags(_case_by_name(raw["vectors"], excluded["caseId"])["input"])
                if not excluded.get("reason"):
                    raise ValueError(f"{excluded['caseId']}: exclusion must state its reason")
                if "sourceTag" in excluded:
                    if excluded["sourceTag"] in PROTOCOL_TAGS or tags != {excluded["sourceTag"]}:
                        raise ValueError(f"{excluded['caseId']}: inexpressible-tag exclusion drift")
                elif tags:
                    raise ValueError(f"{excluded['caseId']}: tagged source input needs its sourceTag")
        elif family["id"] == "signed-scope":
            raw = sources[family["source"]]
            for selected in family["cases"]:
                actual = _artifact_by_id(raw["artifacts"], selected["caseId"])
                if actual["kind"] != selected["kind"]:
                    raise ValueError(f"{selected['caseId']}: artifact kind drift")
                if actual["contentHash"] != selected["sourceExpected"]:
                    raise ValueError(f"{selected['caseId']}: source content hash drift")
                if actual["contentHash"].removeprefix("sha256:") != selected["expected"]["hex"]:
                    raise ValueError(f"{selected['caseId']}: mapped content hash drift")
        elif family["id"] == "sig6-wire":
            raw = sources[family["source"]]
            all_ids = {item["caseId"] for item in family["cases"]}
            all_ids.update(item["caseId"] for item in family["excludedSourceCases"])
            source_ids = {item["name"] for item in raw["vectors"]}
            if all_ids != source_ids:
                raise ValueError("SIG-6 selections and exclusions do not partition the source cases")
            for selected in family["cases"]:
                actual = _case_by_name(raw["vectors"], selected["caseId"])
                if actual["expected"] != selected["sourceExpected"]:
                    raise ValueError(f"{selected['caseId']}: SIG-6 source verdict drift")
                if actual["expected"].upper() != selected["expected"]:
                    raise ValueError(f"{selected['caseId']}: SIG-6 adapter verdict drift")
                try:
                    modules["vectors"].decode_signature_value(actual["value"], legacy_allowed=False)
                    wire_verdict = "ACCEPT"
                except (TypeError, ValueError):
                    wire_verdict = "REJECT"
                if wire_verdict != selected["expected"]:
                    raise ValueError(f"{selected['caseId']}: selected SIG-6 case is not decided by wire encoding alone")
        elif family["id"] == "domain-separated-signing":
            if family.get("advertisedFamily") is not False:
                raise ValueError("bounded F5 profile must not advertise the generic family")
            if family.get("genericFamilyMilestone") != "incomplete":
                raise ValueError("bounded F5 profile must retain the incomplete generic milestone")
            if set(family.get("operations", [])) != {"domainSepSign", "domainSepVerify"}:
                raise ValueError("bounded F5 operation set drift")
            if not family.get("remainingBlocker") or not family.get("requiredHandoffQuestion"):
                raise ValueError("bounded F5 profile must retain its abstention blocker and handoff")
            _validate_control_lines(
                family["controlSource"], _load_bytes_at_revision(family["controlSource"])
            )
            raw = sources[family["source"]]["signing"]
            selected = {case["caseId"]: case for case in family["cases"]}
            if set(selected) != {
                "signing::sign-ascii-hex-hash",
                "signing::verify-ascii-hex-hash",
                "signing::reject-mismatched-ascii-hex-hash",
                "signing::unknown-separator-false",
            }:
                raise ValueError("bounded F5 selected case set drift")
            sign_case = selected["signing::sign-ascii-hex-hash"]
            verify_case = selected["signing::verify-ascii-hex-hash"]
            mismatch_case = selected["signing::reject-mismatched-ascii-hex-hash"]
            unknown_case = selected["signing::unknown-separator-false"]
            primitive_controls = family.get("primitiveControls", [])
            unsupported_cases = family.get("unsupportedCases", [])
            if len(primitive_controls) != 1 or len(unsupported_cases) != 1:
                raise ValueError("bounded F5 must pin one primitive control and one unsupported case")
            raw_digest_control = primitive_controls[0]
            raw_digest_unsupported = unsupported_cases[0]
            unsupported += len(unsupported_cases)
            if raw["separator"] != sign_case["separator"]:
                raise ValueError("domain separator drift")
            if raw["signature"] != sign_case["sourceExpected"]:
                raise ValueError("domain signature source drift")

            jcs, walkthrough = modules["jcs"], modules["walkthrough"]
            for case in [*family["cases"], raw_digest_control, raw_digest_unsupported]:
                if case["caseId"] != "signing::unknown-separator-false" and case["separator"] != BOUNDED_F5_SEPARATOR:
                    raise ValueError(f"{case['caseId']}: bounded F5 case must use {BOUNDED_F5_SEPARATOR}")
            artifact_hash = _sha256(jcs.canonicalize(raw["doc"]).encode("utf-8"))
            if artifact_hash != sign_case["artifactHashHex"]:
                raise ValueError("domain signing artifact hash drift")
            if artifact_hash.encode("ascii").hex() != sign_case["messageBytesHex"]:
                raise ValueError("domain signing message bytes drift")
            payload = (raw["separator"] + artifact_hash).encode("ascii")
            if raw["seed"] != sign_case["privateKeyBytesHex"]:
                raise ValueError("domain signing private seed drift")
            signature = walkthrough.sign_ed25519(bytes.fromhex(sign_case["privateKeyBytesHex"]), payload)
            if signature.hex() != sign_case["expected"]["hex"]:
                raise ValueError("existing Standard Ed25519 helper no longer reproduces the pin")
            if base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii") != raw["signature"]:
                raise ValueError("source signature encoding drift")
            if raw["publicKeyHex"] != verify_case["publicKeyHex"]:
                raise ValueError("domain signing public key drift")
            if bytes.fromhex(verify_case["messageBytesHex"]) != artifact_hash.encode("ascii"):
                raise ValueError("domain verification message bytes drift")
            if verify_case["signatureBytesHex"] != signature.hex() or verify_case["expected"] is not True:
                raise ValueError("domain verification positive case drift")
            public_key = bytes.fromhex(verify_case["publicKeyHex"])
            if not walkthrough.verify_ed25519(public_key, signature, payload):
                raise ValueError("existing Standard Ed25519 verification helper rejected the pin")
            mismatch_message = bytes.fromhex(mismatch_case["messageBytesHex"])
            if (
                len(mismatch_message) != 64
                or any(byte not in b"0123456789abcdef" for byte in mismatch_message)
                or mismatch_message == artifact_hash.encode("ascii")
                or mismatch_case["signatureBytesHex"] != signature.hex()
                or mismatch_case["publicKeyHex"] != public_key.hex()
                or mismatch_case["expected"] is not False
                or walkthrough.verify_ed25519(
                    public_key,
                    signature,
                    raw["separator"].encode("utf-8") + mismatch_message,
                )
            ):
                raise ValueError("bounded F5 in-profile mismatch control drift")
            raw_digest = bytes.fromhex(raw_digest_control["messageBytesHex"])
            raw_digest_payload = raw["separator"].encode("utf-8") + raw_digest
            if (
                raw_digest.hex() != artifact_hash
                or raw_digest_control["signatureBytesHex"] != signature.hex()
                or raw_digest_control["publicKeyHex"] != public_key.hex()
                or raw_digest_control["expected"] is not False
                or walkthrough.verify_ed25519(
                    public_key, signature, raw_digest_payload
                )
            ):
                raise ValueError("existing Standard raw-digest primitive control drift")
            valid_raw_signature = walkthrough.sign_ed25519(
                bytes.fromhex(sign_case["privateKeyBytesHex"]), raw_digest_payload
            )
            if (
                raw_digest_unsupported["messageBytesHex"] != raw_digest.hex()
                or raw_digest_unsupported["signatureBytesHex"] != valid_raw_signature.hex()
                or raw_digest_unsupported["publicKeyHex"] != public_key.hex()
                or raw_digest_unsupported["primitiveVerification"] is not True
                or raw_digest_unsupported["adapterErrorCode"] != "UNSUPPORTED_CASE"
                or not walkthrough.verify_ed25519(
                    public_key, valid_raw_signature, raw_digest_payload
                )
            ):
                raise ValueError("valid raw-digest adapter-boundary case drift")
            separator = unknown_case["separator"]
            if (
                unknown_case["expected"] is not False
                or not isinstance(separator, str)
                or separator == BOUNDED_F5_SEPARATOR
                or DACS_SEPARATOR_SHAPE.fullmatch(separator)
                or unknown_case["messageBytesHex"] != verify_case["messageBytesHex"]
                or unknown_case["signatureBytesHex"] != verify_case["signatureBytesHex"]
                or unknown_case["publicKeyHex"] != verify_case["publicKeyHex"]
            ):
                raise ValueError("unknown-separator verification control drift")
        else:
            raise ValueError(f"unknown release family {family['id']!r}")

    return {
        "families": len(descriptor["families"]),
        "executableCases": executable,
        "boundedCases": bounded,
        "unsupportedCases": unsupported,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("descriptor", nargs="?", type=Path, default=DEFAULT_DESCRIPTOR)
    args = parser.parse_args(argv)
    try:
        counts = validate(args.descriptor.resolve())
    except (
        AttributeError,
        IndexError,
        KeyError,
        OSError,
        RecursionError,
        SyntaxError,
        TypeError,
        ValueError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"adapter release proposal: FAIL: {exc}", file=sys.stderr)
        return 1
    unsupported_label = "mapping" if counts["unsupportedCases"] == 1 else "mappings"
    print(
        "adapter release proposal: PASS "
        f"({counts['executableCases']} advertised-family cases, "
        f"{counts['boundedCases']} bounded F5 cases, "
        f"{counts['unsupportedCases']} unsupported {unsupported_label})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
