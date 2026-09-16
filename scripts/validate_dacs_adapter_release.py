#!/usr/bin/env python3
"""Validate the non-normative issue-270 adapter release proposal."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DESCRIPTOR = (
    ROOT / "conformance" / "interop" / "dacs-adapter-release-proposal-v1.json"
)
EXPECTED_ORIGIN = "https://github.com/DACS-Agent-commerce/DACS-Standard.git"


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_bytes_at_revision(source: dict[str, Any]) -> bytes:
    path = source["path"]
    revision = source["revision"]
    blob = _git("rev-parse", f"{revision}:{path}")
    if blob != source["gitBlob"]:
        raise ValueError(f"{path}: git blob does not match descriptor")
    data = subprocess.run(
        ["git", "show", f"{revision}:{path}"],
        cwd=ROOT,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
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


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load module {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate(descriptor_path: Path = DEFAULT_DESCRIPTOR) -> dict[str, int]:
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    if descriptor.get("schema") != "dacs-adapter-release-proposal/1":
        raise ValueError("unexpected descriptor schema")
    if descriptor.get("status") != "proposal-non-normative":
        raise ValueError("descriptor must remain explicitly non-normative")
    if descriptor.get("protocol", {}).get("id") != "dacs-adapter/1":
        raise ValueError("unexpected adapter protocol")
    if descriptor.get("adapter", {}).get("repository") != EXPECTED_ORIGIN.removesuffix(".git"):
        raise ValueError("adapter repository identity is not DACS-Standard")
    observed_origin = _git("config", "--get", "remote.origin.url")
    if observed_origin not in {EXPECTED_ORIGIN, EXPECTED_ORIGIN.removesuffix(".git")}:
        raise ValueError("working repository origin is not the pinned DACS-Standard origin")

    adapter = descriptor["adapter"]
    source = adapter["source"]
    source_bytes = (ROOT / source["path"]).read_bytes()
    if _sha256(source_bytes) != source["sha256"]:
        raise ValueError("adapter source sha256 does not match descriptor")
    if _git("hash-object", "--", source["path"]) != source["gitBlob"]:
        raise ValueError("adapter source git blob does not match descriptor")
    if _git("rev-parse", f"HEAD:{source['path']}") != source["gitBlob"]:
        raise ValueError("adapter source is not the pinned committed blob at HEAD")
    descriptor_relative = str(descriptor_path.relative_to(ROOT))
    if _git("hash-object", "--", descriptor_relative) != _git(
        "rev-parse", f"HEAD:{descriptor_relative}"
    ):
        raise ValueError("release descriptor is not committed at HEAD")

    wrapped = adapter["wrappedStandard"]
    if _git("rev-parse", f"{wrapped['revision']}^{{tree}}") != wrapped["tree"]:
        raise ValueError("wrapped Standard tree mismatch")
    for primitive in wrapped["primitives"]:
        path = primitive["path"]
        current = (ROOT / path).read_bytes()
        if _sha256(current) != primitive["sha256"]:
            raise ValueError(f"wrapped primitive sha256 mismatch: {path}")
        if _git("hash-object", "--", path) != primitive["gitBlob"]:
            raise ValueError(f"wrapped primitive working blob mismatch: {path}")
        if _git("rev-parse", f"{wrapped['revision']}:{path}") != primitive["gitBlob"]:
            raise ValueError(f"wrapped primitive revision blob mismatch: {path}")

    sources = {
        name: _load_json_at_revision(value)
        for name, value in descriptor["sources"].items()
    }
    executable = 0
    bounded = 0
    unsupported = 0
    for family in descriptor["families"]:
        status = family["status"]
        if status == "bounded-operation-profile":
            bounded += len(family["cases"])
        elif status != "executable":
            raise ValueError(f"family {family['id']}: invalid status {status!r}")
        else:
            executable += len(family["cases"])

        if family["id"] == "canonicalization":
            raw = sources[family["source"]]
            for selected in family["cases"]:
                actual = _case_by_name(raw["vectors"], selected["caseId"])
                if actual["expected"] != selected["sourceExpected"]:
                    raise ValueError(f"{selected['caseId']}: canonical source verdict drift")
                if actual["expected"] == "pass":
                    if actual["canonicalUtf8Hex"] != selected["expected"]["hex"]:
                        raise ValueError(f"{selected['caseId']}: canonical bytes drift")
                elif actual["expectedErrorCode"] != selected["sourceExpectedErrorCode"]:
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
        elif family["id"] == "domain-separated-signing":
            if family.get("advertisedFamily") is not False:
                raise ValueError("bounded F5 profile must not advertise the generic family")
            if family.get("genericFamilyMilestone") != "incomplete":
                raise ValueError("bounded F5 profile must retain the incomplete generic milestone")
            if set(family.get("operations", [])) != {"domainSepSign", "domainSepVerify"}:
                raise ValueError("bounded F5 operation set drift")
            if not family.get("remainingBlocker") or not family.get("requiredHandoffQuestion"):
                raise ValueError("bounded F5 profile must retain its abstention blocker and handoff")
            _load_bytes_at_revision(family["controlSource"])
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

            sys.path.insert(0, str(ROOT / "scripts"))
            jcs = _load_module(ROOT / "scripts" / "jcs.py", "dacs_release_jcs")
            walkthrough = _load_module(
                ROOT / "scripts" / "run_lifecycle_walkthrough.py", "dacs_release_walkthrough"
            )
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
            if unknown_case["expected"] is not False:
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
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
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
