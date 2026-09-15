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


def _load_json_at_revision(source: dict[str, Any]) -> dict[str, Any]:
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
    return json.loads(data)


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
    unsupported = 0
    for family in descriptor["families"]:
        status = family["status"]
        if status == "blocked":
            unsupported += len(family["cases"])
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
            if (
                family["operation"] is not None
                or not family.get("blocker")
                or family.get("firstMilestone") != "incomplete"
                or not family.get("requiredHandoffQuestion")
            ):
                raise ValueError("blocked F5 mapping must have no advertised operation and an exact blocker")
            raw = sources[family["source"]]["signing"]
            selected = family["cases"][0]
            if selected["caseId"] != "signing":
                raise ValueError("unexpected domain-separated signing source selector")
            if raw["separator"] != selected["separator"]:
                raise ValueError("domain separator drift")
            if raw["signature"] != selected["sourceExpected"]:
                raise ValueError("domain signature source drift")
            if raw["publicKeyHex"] != selected["publicKeyHex"]:
                raise ValueError("domain signing public key drift")

            sys.path.insert(0, str(ROOT / "scripts"))
            jcs = _load_module(ROOT / "scripts" / "jcs.py", "dacs_release_jcs")
            walkthrough = _load_module(
                ROOT / "scripts" / "run_lifecycle_walkthrough.py", "dacs_release_walkthrough"
            )
            artifact_hash = _sha256(jcs.canonicalize(raw["doc"]).encode("utf-8"))
            if artifact_hash != selected["artifactHashHex"]:
                raise ValueError("domain signing artifact hash drift")
            payload = (raw["separator"] + artifact_hash).encode("ascii")
            signature = walkthrough.sign_ed25519(bytes.fromhex(raw["seed"]), payload)
            if signature.hex() != selected["expectedSignatureHex"]:
                raise ValueError("existing Standard Ed25519 helper no longer reproduces the pin")
            if base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii") != raw["signature"]:
                raise ValueError("source signature encoding drift")
            if not walkthrough.verify_ed25519(bytes.fromhex(raw["publicKeyHex"]), signature, payload):
                raise ValueError("existing Standard Ed25519 verification helper rejected the pin")
        else:
            raise ValueError(f"unknown release family {family['id']!r}")

    return {
        "families": len(descriptor["families"]),
        "executableCases": executable,
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
    print(
        "adapter release proposal: PASS "
        f"({counts['families']} families, {counts['executableCases']} executable cases, "
        f"{counts['unsupportedCases']} unsupported mappings)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
