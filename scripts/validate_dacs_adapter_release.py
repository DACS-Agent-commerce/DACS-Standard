#!/usr/bin/env python3
"""Validate the non-normative issue-270 adapter release proposal."""

import os
import sys

_CHECKOUT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def _outside_checkout(entry: str) -> bool:
    resolved = os.path.realpath(entry or os.curdir)
    return resolved != _CHECKOUT and not resolved.startswith(_CHECKOUT + os.sep)


if __name__ == "__main__":
    # Keep this checkout off the import path so an untracked file in it cannot
    # shadow a standard-library module imported below.  (No ``from __future__``
    # import precedes this: it too would resolve against the script directory.)
    sys.path[:] = [entry for entry in sys.path if _outside_checkout(entry)]

import argparse
import ast
import base64
import hashlib
import json
import re
import subprocess
import types
from importlib.machinery import BuiltinImporter, FrozenImporter, PathFinder
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DESCRIPTOR = (
    ROOT / "conformance" / "interop" / "dacs-adapter-release-proposal-v1.json"
)
EXPECTED_ORIGIN = "https://github.com/DACS-Agent-commerce/DACS-Standard.git"
ADAPTER_SOURCE = "scripts/dacs_adapter.py"
BOUNDED_F5_SEPARATOR = "dacs-listing:v1:"
DACS_SEPARATOR_PREFIX = "dacs"
CONTROL_TEST = "test_golden_signature_rejects_raw_digest_preimage"
PROTOCOL_TAGS = {"bytes", "bigint"}
FAMILY_OPERATION = {
    "canonicalization": "canonicalize",
    "signed-scope": "signedScopeHash",
    "sig6-wire": "signatureValueVerdict",
}
F5_PROFILE = "listing-single-hash-golden-v1"
# The shapes the adapter's signedScopeHash hashes: discriminator, required members,
# and the only top-level *Version members it admits.
HASHABLE_SHAPES = {
    "SettlementEvidence": ("evidenceVersion", {"jobId", "phase", "outcome", "signature"}, {"evidenceVersion"}),
    "AttestationBundle": (
        "bundleVersion",
        {"jobId", "outcome", "phaseSummary", "signatures"},
        {"bundleVersion", "recipeRegistryVersion", "railRegistryVersion"},
    ),
}
HEX40 = re.compile(r"[0-9a-f]{40}")
PIN_KEYS = {"path", "sha256", "gitBlob"}
SOURCE_KEYS = PIN_KEYS | {"revision"}
# The members each descriptor object may carry.  Anything else would be an
# unreviewed claim (for example ``"normative": true``) and is refused.
DESCRIPTOR_KEYS = {"schema", "status", "issue", "protocol", "adapter", "sources", "families"}
PROTOCOL_KEYS = SOURCE_KEYS | {"id", "repository", "exportedCompanionInputs"}
ADAPTER_KEYS = {"name", "version", "repository", "provenanceCodebase", "source", "wrappedStandard", "limitations"}
SOURCE_PATHS = {
    "canonicalization": "conformance/vectors/security/canonical-json-v0.1.json",
    "signedScope": "conformance/vectors/dacs-v0.1-happy-path.json",
    "sig6": "conformance/vectors/security/signature-value-encoding-v0.1.json",
    "domainSeparatedSigning": "conformance/vectors/golden.json",
}
SOURCE_NAMES = set(SOURCE_PATHS)
FAMILY_SOURCE = {
    "canonicalization": "canonicalization",
    "signed-scope": "signedScope",
    "sig6-wire": "sig6",
    "domain-separated-signing": "domainSeparatedSigning",
}
FAMILY_KEYS = {
    "canonicalization": {"id", "operation", "status", "source", "cases", "unsupportedSourceCases", "excludedSourceCases"},
    "signed-scope": {"id", "operation", "status", "source", "cases"},
    "sig6-wire": {"id", "operation", "status", "source", "cases", "excludedSourceCases"},
    "domain-separated-signing": {
        "id", "operations", "status", "advertisedFamily", "profile", "source", "controlSource", "cases",
        "primitiveControls", "unsupportedCases", "genericFamilyMilestone", "remainingBlocker",
        "requiredHandoffQuestion",
    },
}
ENTRY_KEYS = {
    ("canonicalization", "cases"): {"caseId", "sourceExpected", "expected", "sourceExpectedErrorCode", "expectedErrorCode"},
    ("canonicalization", "unsupportedSourceCases"): {
        "caseId", "sourceExpected", "sourceExpectedErrorCode", "adapterErrorCode", "reason",
    },
    ("canonicalization", "excludedSourceCases"): {"caseId", "sourceTag", "reason"},
    ("signed-scope", "cases"): {"caseId", "kind", "sourceExpected", "expected"},
    ("sig6-wire", "cases"): {"caseId", "sourceExpected", "expected"},
    ("sig6-wire", "excludedSourceCases"): {"caseId", "reason"},
    ("domain-separated-signing", "cases"): {
        "caseId", "operation", "separator", "artifactHashHex", "messageBytesHex", "privateKeyBytesHex",
        "sourceExpected", "expected", "signatureBytesHex", "publicKeyHex", "derivation",
    },
    ("domain-separated-signing", "primitiveControls"): {
        "caseId", "separator", "messageBytesHex", "signatureBytesHex", "publicKeyHex", "expected", "scope",
    },
    ("domain-separated-signing", "unsupportedCases"): {
        "caseId", "operation", "separator", "messageBytesHex", "signatureBytesHex", "publicKeyHex",
        "primitiveVerification", "adapterErrorCode", "reason",
    },
}
# sha256 of the reviewed prose claims and of the neutral-protocol pins, which
# cannot be checked offline.  Changing any of them is a deliberate, visible edit
# here, never a silent descriptor change.
REVIEWED_CLAIMS_SHA256 = "b499eff09625d5352c494bd09593424e2885e83902635dccc4fb56c3e3ec29d1"
HEX64 = re.compile(r"[0-9a-f]{64}")
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
    environment["GIT_ALLOW_PROTOCOL"] = ""  # refuse every transport, whatever the configuration allows
    environment["GIT_NO_LAZY_FETCH"] = "1"
    return subprocess.run(
        ["git", "-C", str(ROOT), "-c", "protocol.allow=never", *args],
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


def _safe_relative_path(path: Any) -> bool:
    """A plain repository-relative path that cannot be read as a Git option."""

    return (
        isinstance(path, str)
        and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]*", path) is not None
        and ".." not in path.split("/")
        and "//" not in path
    )


def _load_bytes_at_revision(source: dict[str, Any]) -> bytes:
    path = source["path"]
    revision = source["revision"]
    if not HEX40.fullmatch(str(revision)) or not _safe_relative_path(path):
        raise ValueError("pinned source revision and path must be a commit id and a relative path")
    blob = _git("rev-parse", f"{revision}:{path}")
    if blob != source["gitBlob"]:
        raise ValueError(f"{path}: git blob does not match descriptor")
    data = _git_run("show", f"{revision}:{path}").stdout
    if _sha256(data) != source["sha256"]:
        raise ValueError(f"{path}: sha256 does not match descriptor")
    # The pinned bytes come from the release's Git objects; later edits to the
    # working file neither change them nor invalidate the release.
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


def _load_verified_module(relative: str, data: bytes, expected_sha256: str, name: str) -> types.ModuleType:
    """Execute exactly the pinned release bytes; never a working file or cached bytecode."""

    path = ROOT / relative
    if _sha256(data) != expected_sha256:
        raise ValueError(f"wrapped primitive sha256 mismatch: {relative}")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


class _StandardLibraryOnly:
    """While wrapped modules execute, refuse imports outside the standard library.

    They put this checkout's scripts directory on ``sys.path`` and try an optional
    ``cryptography`` import, so without this an untracked package there would run.
    """

    @staticmethod
    def find_spec(fullname: str, path: Any = None, target: Any = None) -> Any:
        if fullname.partition(".")[0] not in sys.stdlib_module_names:
            raise ModuleNotFoundError(f"refusing unpinned import {fullname!r}", name=fullname)
        for finder in (BuiltinImporter, FrozenImporter):
            spec = finder.find_spec(fullname, path, target)
            if spec is not None:
                return spec
        if path is None:
            path = [entry for entry in sys.path if _outside_checkout(entry)]
        spec = PathFinder.find_spec(fullname, path, target)
        if spec is None:
            raise ModuleNotFoundError(f"no standard-library module named {fullname!r}", name=fullname)
        return spec


def _load_primitives(primitives: dict[str, str], release: dict[str, bytes]) -> dict[str, types.ModuleType]:
    """Load the wrapped modules from verified bytes, resolving their local imports to them."""

    names = {"jcs": "scripts/jcs.py", "specsource": "scripts/specsource.py"}
    previous = {name: sys.modules.get(name) for name in names}
    guard = _StandardLibraryOnly()
    sys.meta_path.insert(0, guard)
    try:
        loaded = {
            name: _load_verified_module(relative, release[relative], primitives[relative], name)
            for name, relative in names.items()
        }
    except BaseException:
        sys.meta_path.remove(guard)
        raise
    sys.modules.update(loaded)  # ``import jcs`` / ``import specsource`` must see the verified modules
    try:
        loaded["walkthrough"] = _load_verified_module(
            "scripts/run_lifecycle_walkthrough.py",
            release["scripts/run_lifecycle_walkthrough.py"],
            primitives["scripts/run_lifecycle_walkthrough.py"],
            "dacs_release_walkthrough",
        )
        loaded["vectors"] = _load_verified_module(
            "scripts/validate_conformance_vectors.py",
            release["scripts/validate_conformance_vectors.py"],
            primitives["scripts/validate_conformance_vectors.py"],
            "dacs_release_vectors",
        )
    finally:
        sys.meta_path.remove(guard)
        for name, module in previous.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module
    return loaded


def _validate_control_lines(control: dict[str, Any], data: bytes) -> None:
    match = re.fullmatch(r"([1-9][0-9]*)-([1-9][0-9]*)", str(control.get("lines", "")))
    test_name = control.get("test")
    if match is None or test_name != CONTROL_TEST:
        raise ValueError(f"bounded F5 control source must be {CONTROL_TEST} with its line range")
    start, end = int(match.group(1)), int(match.group(2))
    lines = data.decode("utf-8").splitlines()
    definition = f"    def {test_name}(self):"
    if start > end or end > len(lines) or lines[start - 1] != definition:
        raise ValueError("bounded F5 control line range does not start at the named test")
    if lines.count(definition) != 1 or (start > 1 and lines[start - 2].lstrip().startswith("@")):
        raise ValueError("bounded F5 control test must be defined once and undecorated")
    body_end = start
    for number in range(start + 1, len(lines) + 1):
        text = lines[number - 1]
        if text.strip() and not text.startswith("        "):
            break
        if text.strip():
            body_end = number
    if end != body_end:
        raise ValueError("bounded F5 control line range does not cover exactly the named test")
    body = "\n".join(lines[start - 1 : end])
    if "bytes.fromhex(self.digest_hex)" not in body or "assertRaises(InvalidSignature)" not in body:
        raise ValueError("bounded F5 control test no longer rejects the raw-digest preimage")


def validate(descriptor_path: Path = DEFAULT_DESCRIPTOR) -> dict[str, int]:
    if not descriptor_path.is_file():
        raise ValueError("release descriptor is not a regular file")
    descriptor_bytes = descriptor_path.read_bytes()
    descriptor = json.loads(descriptor_bytes)
    origins = _git("config", "--local", "--get-all", "remote.origin.url").splitlines()
    effective = _git("remote", "get-url", "--all", "origin").splitlines()
    same_repository = {
        f"{prefix}DACS-Agent-commerce/DACS-Standard"
        for prefix in ("https://github.com/", "ssh://git@github.com/", "git@github.com:")
    }
    if (
        len(origins) != 1
        or origins[0] not in {EXPECTED_ORIGIN, EXPECTED_ORIGIN.removesuffix(".git")}
        or len(effective) != 1
        or effective[0].removesuffix(".git") not in same_repository
    ):
        raise ValueError("working repository origin is not the pinned DACS-Standard origin")
    descriptor_relative = descriptor_path.relative_to(ROOT).as_posix()
    if _git_blob_id(descriptor_bytes) != _git("rev-parse", f"HEAD:{descriptor_relative}"):
        raise ValueError("release descriptor is not committed at HEAD")
    source = descriptor.get("adapter", {}).get("source", {})
    if _git("rev-parse", f"HEAD:{ADAPTER_SOURCE}") != source.get("gitBlob"):
        raise ValueError("adapter source is not the pinned committed blob at HEAD")
    return validate_release(descriptor)


def _closed(value: Any, allowed: set[str], where: str) -> None:
    if not isinstance(value, dict) or not set(value) <= allowed:
        extra = sorted(set(value) - allowed) if isinstance(value, dict) else type(value).__name__
        raise ValueError(f"{where}: unexpected descriptor members {extra}")


def _check_closed_schema(descriptor: dict[str, Any]) -> None:
    _closed(descriptor, DESCRIPTOR_KEYS, "descriptor")
    _closed(descriptor["protocol"], PROTOCOL_KEYS, "protocol")
    for pin in descriptor["protocol"]["exportedCompanionInputs"]:
        _closed(pin, PIN_KEYS, "protocol companion input")
    adapter = descriptor["adapter"]
    _closed(adapter, ADAPTER_KEYS, "adapter")
    _closed(adapter["source"], PIN_KEYS, "adapter source")
    _closed(adapter["wrappedStandard"], {"revision", "tree", "primitives"}, "wrapped Standard")
    for primitive in adapter["wrappedStandard"]["primitives"]:
        _closed(primitive, PIN_KEYS, "wrapped primitive")
    if set(descriptor["sources"]) != SOURCE_NAMES:
        raise ValueError("descriptor sources differ from the four pinned corpora")
    for name, source in descriptor["sources"].items():
        _closed(source, SOURCE_KEYS, f"source {name}")
    for family in descriptor["families"]:
        family_id = family.get("id")
        if family_id not in FAMILY_KEYS:
            raise ValueError(f"unknown release family {family_id!r}")
        _closed(family, FAMILY_KEYS[family_id], f"family {family_id}")
        for (owner, key), allowed in ENTRY_KEYS.items():
            if owner == family_id:
                for entry in family.get(key, []):
                    _closed(entry, allowed, f"{family_id}.{key}")
                    if isinstance(entry.get("expected"), dict):
                        _closed(entry["expected"], {"hex"}, f"{family_id}.{key}.expected")
        if "controlSource" in family:
            _closed(family["controlSource"], SOURCE_KEYS | {"test", "lines"}, "control source")


def reviewed_claims_sha256(descriptor: dict[str, Any]) -> str:
    """Digest of every prose claim and the neutral-protocol pins."""

    families = {}
    for family in descriptor["families"]:
        notes = sorted(
            [key, entry["caseId"], entry[field]]
            for key in ("cases", "unsupportedSourceCases", "excludedSourceCases", "primitiveControls", "unsupportedCases")
            for entry in family.get(key, [])
            for field in ("reason", "scope", "derivation")
            if field in entry
        )
        families[family["id"]] = {
            "flags": {
                key: family[key]
                for key in ("advertisedFamily", "genericFamilyMilestone", "remainingBlocker", "requiredHandoffQuestion")
                if key in family
            },
            "notes": notes,
        }
    claims = {
        "status": descriptor.get("status"),
        "issue": descriptor.get("issue"),
        "protocol": descriptor.get("protocol"),
        "adapter": {key: descriptor["adapter"].get(key) for key in ("name", "version", "limitations")},
        "families": families,
    }
    return _sha256(json.dumps(claims, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def validate_release(descriptor: dict[str, Any]) -> dict[str, int]:
    """Check descriptor content against the working tree and its pinned revisions."""

    _check_closed_schema(descriptor)
    if reviewed_claims_sha256(descriptor) != REVIEWED_CLAIMS_SHA256:
        raise ValueError(
            "descriptor claims or neutral-protocol pins changed; review them and update REVIEWED_CLAIMS_SHA256"
        )
    if descriptor.get("schema") != "dacs-adapter-release-proposal/1":
        raise ValueError("unexpected descriptor schema")
    if descriptor.get("status") != "proposal-non-normative":
        raise ValueError("descriptor must remain explicitly non-normative")
    protocol = descriptor.get("protocol", {})
    if protocol.get("id") != "dacs-adapter/1":
        raise ValueError("unexpected adapter protocol")
    for pin in [protocol, *protocol.get("exportedCompanionInputs", [])]:
        if not (HEX64.fullmatch(str(pin.get("sha256"))) and HEX40.fullmatch(str(pin.get("gitBlob")))):
            raise ValueError("neutral protocol pins must be sha256 and Git blob digests")
    if not HEX40.fullmatch(str(protocol.get("revision"))):
        raise ValueError("neutral protocol revision must be an immutable commit id")
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
    release: dict[str, bytes] = {}
    for primitive in wrapped["primitives"]:
        path = primitive["path"]
        data = _git_run("show", f"{wrapped['revision']}:{path}").stdout
        if _sha256(data) != primitive["sha256"]:
            raise ValueError(f"wrapped primitive sha256 mismatch: {path}")
        if _git_blob_id(data) != primitive["gitBlob"]:
            raise ValueError(f"wrapped primitive revision blob mismatch: {path}")
        release[path] = data
    for name, source in descriptor["sources"].items():
        if source.get("path") != SOURCE_PATHS[name] or source.get("revision") != wrapped["revision"]:
            raise ValueError(f"source {name} must pin {SOURCE_PATHS[name]} at the wrapped revision")
    primitive_sha256 = {primitive["path"]: primitive["sha256"] for primitive in wrapped["primitives"]}

    sources = {
        name: _load_json_at_revision(value)
        for name, value in descriptor["sources"].items()
    }
    executable = 0
    bounded = 0
    unsupported = 0
    modules = _load_primitives(primitive_sha256, release)
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
        if family.get("source") != FAMILY_SOURCE[family["id"]]:
            raise ValueError(f"family {family['id']}: source corpus drift")
        if family["id"] in FAMILY_OPERATION and (
            family.get("operation") != FAMILY_OPERATION[family["id"]]
            or any("operation" in item for item in family["cases"])
        ):
            raise ValueError(f"family {family['id']}: operation drift")
        for key in ("unsupportedSourceCases", "excludedSourceCases", "unsupportedCases"):
            if not all(_bounded_text(item.get("reason"), 1024) for item in family.get(key, [])):
                raise ValueError(f"family {family['id']}: every {key} entry must state its reason")
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
                if _tags(actual["input"]) != {"bigint"}:
                    raise ValueError(f"{selected['caseId']}: only a BigInt host type is an unsupported mapping")
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
                if selected["kind"] not in HASHABLE_SHAPES:
                    raise ValueError(f"{selected['caseId']}: the adapter does not hash {selected['kind']}")
                discriminator, required, version_members = HASHABLE_SHAPES[selected["kind"]]
                body = actual["artifact"]
                if (
                    body.get(discriminator) != "1"
                    or not required <= set(body)
                    or not {member for member in body if member.endswith("Version")} <= version_members
                ):
                    raise ValueError(f"{selected['caseId']}: source artifact is outside the hashable shape")
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
            if family.get("operations") != ["domainSepSign", "domainSepVerify"]:
                raise ValueError("bounded F5 operation set drift")
            if family.get("profile") != F5_PROFILE:
                raise ValueError("bounded F5 profile identifier drift")
            if "operation" in family or any(
                case.get("operation")
                != ("domainSepSign" if case["caseId"] == "signing::sign-ascii-hex-hash" else "domainSepVerify")
                for case in [*family["cases"], *family.get("unsupportedCases", [])]
            ):
                raise ValueError("bounded F5 case operation drift")
            if not family.get("remainingBlocker") or not family.get("requiredHandoffQuestion"):
                raise ValueError("bounded F5 profile must retain its abstention blocker and handoff")
            control = family["controlSource"]
            if control.get("path") != "tests/test_flow_trace_signing.py" or control.get("revision") != wrapped["revision"]:
                raise ValueError("bounded F5 control source must be the flow-trace test at the wrapped revision")
            _validate_control_lines(control, _load_bytes_at_revision(control))
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
                or separator.startswith(DACS_SEPARATOR_PREFIX)
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
