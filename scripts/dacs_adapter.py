#!/usr/bin/env python3
"""Bounded ``dacs-adapter/1`` wrapper over pinned DACS-Standard primitives.

This proposal adapter is non-normative.  It verifies the repository origin and
the committed blobs named by its release descriptor, then executes exactly
those verified bytes for the existing canonicalisation, signed-scope, and
signature helpers.  Only the interpreter's standard library may be imported
alongside them.  It performs no network or substrate operations.
"""

from __future__ import annotations

import os
import sys

# The directory holding this script is sys.path[0].  Remove the checkout's own
# directories before any further import so an untracked file in this repository
# cannot shadow a standard-library module.
_SCRIPT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
_CHECKOUT_DIRECTORIES = (_SCRIPT_DIRECTORY, os.path.dirname(_SCRIPT_DIRECTORY))


def _outside_checkout(entry: str) -> bool:
    return os.path.realpath(entry or os.curdir) not in _CHECKOUT_DIRECTORIES


sys.path[:] = [entry for entry in sys.path if _outside_checkout(entry)]

import hashlib  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import subprocess  # noqa: E402
import types  # noqa: E402
import unicodedata  # noqa: E402
from importlib.machinery import BuiltinImporter, FrozenImporter, PathFinder  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402


PROTOCOL = "dacs-adapter/1"
EXPECTED_ORIGIN = "https://github.com/DACS-Agent-commerce/DACS-Standard.git"
ROOT = Path(__file__).resolve().parents[1]
DESCRIPTOR = ROOT / "conformance" / "interop" / "dacs-adapter-release-proposal-v1.json"
ADAPTER_SOURCE = "scripts/dacs_adapter.py"
# Every repository module this adapter executes, in load order.  The release
# descriptor must pin exactly these paths; each one runs from the bytes that were
# verified, never from a re-read file or cached bytecode.
WRAPPED_MODULES = (
    ("jcs", "scripts/jcs.py"),
    ("specsource", "scripts/specsource.py"),
    ("run_lifecycle_walkthrough", "scripts/run_lifecycle_walkthrough.py"),
    ("validate_conformance_vectors", "scripts/validate_conformance_vectors.py"),
)
OPERATIONS = (
    "canonicalize",
    "signedScopeHash",
    "signatureValueVerdict",
    "domainSepSign",
    "domainSepVerify",
)
MAX_REQUEST_BYTES = 1_048_576
MAX_REQUEST_ID_CHARS = 256
MAX_PARAMS = 5
MAX_DIAGNOSTIC_CHARS = 320
MAX_STDERR_LINE_CHARS = 1024
BOUNDED_F5_SEPARATOR = "dacs-listing:v1:"
DACS_SEPARATOR_SHAPE = re.compile(r"dacs[-a-z0-9]*:v[0-9]+:")
# Exclusive artifact type discriminators: the CORE §11.2.5 version-signalling
# list, DACS-4 §9.7 LegacyTransitionSettlementEvidence, and the wrapped
# validator's DACS-2 composite-record discriminator.  signedScopeHash refuses a
# record carrying any discriminator besides its own instead of hashing a
# type-ambiguous shape.
TYPE_DISCRIMINATORS = frozenset(
    {
        "agreementVersion",
        "authenticatedWindowDerivationVersion",
        "bundleVersion",
        "currentUseAuthenticatedWindowDerivationVersion",
        "currentUseReplayableDerivationVersion",
        "dacsVersion",
        "evidenceBoundFaultBundleVersion",
        "evidenceVersion",
        "faultBundleVersion",
        "finalityBoundEvidenceFaultBundleVersion",
        "finalityBoundEvidenceVersion",
        "finalityObservationResponseVersion",
        "finalityResolutionContextVersion",
        "identityBoundAgreementVersion",
        "identityBoundPayeeAgreementVersion",
        "legacyBundleCheckpointBindingVersion",
        "legacyBundleCheckpointVersion",
        "legacyTransitionEvidenceVersion",
        "participationAdmissionVersion",
        "payeeBoundAgreementVersion",
        "ratingVersion",
        "recordVersion",
        "resultVersion",
        "revocationStateHeadVersion",
        "sealedAuctionRecordVersion",
        "sealedSelectionAgreementVersion",
        "sealedSelectionReceiptVersion",
    }
)
# Variables that would point the provenance checks at another repository.
GIT_REPOSITORY_ENV = frozenset(
    {
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
)


class AdapterError(Exception):
    """A controlled adapter-protocol failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _clean_message(value: object) -> str:
    text = " ".join(str(value).splitlines()).strip()
    if not text:
        text = "operation failed"
    return text[:MAX_DIAGNOSTIC_CHARS]


def _stderr(text: str) -> None:
    """Write one bounded diagnostic line of printable ASCII."""

    line = "".join(
        character if " " <= character <= "~" else character.encode("unicode_escape").decode("ascii")
        for character in text
    )
    print(line[:MAX_STDERR_LINE_CHARS], file=sys.stderr, flush=True)


def _git(*args: str) -> str:
    environment = {key: value for key, value in os.environ.items() if key not in GIT_REPOSITORY_ENV}
    environment["GIT_TERMINAL_PROMPT"] = "0"
    try:
        completed = subprocess.run(
            ["git", "-C", str(ROOT), *args],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"provenance git check failed: {_clean_message(exc)}") from exc
    return completed.stdout.strip()


def _git_blob_id(data: bytes) -> str:
    # Git's object id for these exact bytes.  The sha256 pin carries the digest
    # strength; this binds the same bytes to the committed blob.
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def _read_committed_bytes(relative: str, *, expected_sha256: object, expected_blob: object) -> bytes:
    """Read a pinned file once and return it only if it is the committed HEAD blob."""

    path = ROOT / relative
    if not path.is_file():
        raise RuntimeError(f"missing provenance-pinned file: {relative}")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise RuntimeError(f"sha256 mismatch for provenance-pinned file: {relative}")
    if _git_blob_id(data) != expected_blob:
        raise RuntimeError(f"working blob mismatch for provenance-pinned file: {relative}")
    if _git("rev-parse", f"HEAD:{relative}") != expected_blob:
        raise RuntimeError(f"file is not the expected committed HEAD blob: {relative}")
    return data


def _verify_provenance() -> tuple[dict[str, Any], str, dict[str, bytes]]:
    if not hasattr(sys, "stdlib_module_names"):
        raise RuntimeError("Python 3.10 or later is required to confine imports")
    if Path(_git("rev-parse", "--show-toplevel")).resolve() != ROOT:
        raise RuntimeError("adapter checkout is not the root of its Git work tree")
    observed_origin = _git("config", "--local", "--get", "remote.origin.url")
    if observed_origin not in {EXPECTED_ORIGIN, EXPECTED_ORIGIN.removesuffix(".git")}:
        raise RuntimeError("repository origin does not match the pinned DACS-Standard origin")

    descriptor_relative = DESCRIPTOR.relative_to(ROOT).as_posix()
    try:
        descriptor_bytes = DESCRIPTOR.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"cannot read adapter release descriptor: {_clean_message(exc)}") from exc
    if _git_blob_id(descriptor_bytes) != _git("rev-parse", f"HEAD:{descriptor_relative}"):
        raise RuntimeError("adapter release descriptor is not committed at HEAD")
    try:
        descriptor = json.loads(descriptor_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read adapter release descriptor: {_clean_message(exc)}") from exc

    if descriptor.get("schema") != "dacs-adapter-release-proposal/1":
        raise RuntimeError("unexpected adapter release descriptor schema")
    if descriptor.get("protocol", {}).get("id") != PROTOCOL:
        raise RuntimeError("adapter descriptor protocol mismatch")
    adapter = descriptor.get("adapter", {})
    repository = EXPECTED_ORIGIN.removesuffix(".git")
    if adapter.get("repository") != repository:
        raise RuntimeError("adapter descriptor repository is not DACS-Standard")
    if adapter.get("provenanceCodebase") != repository.removeprefix("https://"):
        raise RuntimeError("adapter codebase identity must be the revision-free DACS-Standard codebase")

    source = adapter.get("source", {})
    if source.get("path") != ADAPTER_SOURCE or (ROOT / ADAPTER_SOURCE).resolve() != Path(__file__).resolve():
        raise RuntimeError("adapter release descriptor does not pin this adapter source")
    _read_committed_bytes(
        ADAPTER_SOURCE,
        expected_sha256=source.get("sha256"),
        expected_blob=source.get("gitBlob"),
    )

    wrapped = adapter.get("wrappedStandard", {})
    revision = wrapped.get("revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise RuntimeError("wrapped Standard revision is not an immutable commit id")
    if _git("rev-parse", f"{revision}^{{commit}}") != revision:
        raise RuntimeError("wrapped Standard revision does not resolve to its pinned commit")
    if _git("rev-parse", f"{revision}^{{tree}}") != wrapped.get("tree"):
        raise RuntimeError("wrapped Standard tree does not match the release descriptor")

    primitives = wrapped.get("primitives")
    if not isinstance(primitives, list) or not all(isinstance(item, dict) for item in primitives):
        raise RuntimeError("adapter descriptor has malformed wrapped primitives")
    pinned_paths = [item.get("path") for item in primitives]
    if sorted(pinned_paths, key=str) != sorted(relative for _, relative in WRAPPED_MODULES):
        raise RuntimeError("wrapped primitive pins do not match the modules this adapter executes")
    verified: dict[str, bytes] = {}
    for primitive in primitives:
        relative = primitive["path"]
        if _git("rev-parse", f"{revision}:{relative}") != primitive.get("gitBlob"):
            raise RuntimeError(f"wrapped revision blob mismatch for {relative}")
        verified[relative] = _read_committed_bytes(
            relative,
            expected_sha256=primitive.get("sha256"),
            expected_blob=primitive.get("gitBlob"),
        )
    return descriptor, observed_origin, verified


class _StandardLibraryOnly:
    """Import guard: after verification only the standard library may be imported.

    Wrapped modules are placed in ``sys.modules`` from their verified bytes before
    anything imports them, so a request for any other module name is unpinned
    code and is refused.  Standard modules resolve only outside this checkout.
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


def _load_wrapped_modules(verified: dict[str, bytes]) -> dict[str, types.ModuleType]:
    sys.meta_path.insert(0, _StandardLibraryOnly())
    loaded: dict[str, types.ModuleType] = {}
    for name, relative in WRAPPED_MODULES:
        path = ROOT / relative
        module = types.ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        exec(compile(verified[relative], str(path), "exec", dont_inherit=True), module.__dict__)
        loaded[name] = module
    return loaded


# Provenance checks intentionally precede execution of the wrapped implementation.
try:
    _RELEASE, _OBSERVED_ORIGIN, _VERIFIED = _verify_provenance()
    _WRAPPED = _load_wrapped_modules(_VERIFIED)
except Exception as exc:  # fail closed with one bounded diagnostic, never a traceback
    if __name__ == "__main__":
        _stderr(f"dacs-adapter: unavailable: {_clean_message(exc)}")
        raise SystemExit(1)
    raise
_jcs = _WRAPPED["jcs"]
_sign_ed25519 = _WRAPPED["run_lifecycle_walkthrough"].sign_ed25519
_verify_ed25519 = _WRAPPED["run_lifecycle_walkthrough"].verify_ed25519
_artifact_hash_hex = _WRAPPED["validate_conformance_vectors"].artifact_hash_hex
_decode_signature_value = _WRAPPED["validate_conformance_vectors"].decode_signature_value


def _decode_tagged(root: Any) -> Any:
    """Decode byte tags; abstain on a host type only once the request is well formed."""

    holder: list[Any] = [root]
    stack: list[tuple[Any, Any, Any]] = [(holder, 0, root)]
    host_type_unsupported = False
    while stack:
        parent, key, value = stack.pop()
        if isinstance(value, dict) and "$dacsType" in value:
            tag = value.get("$dacsType")
            if tag == "bytes" and set(value) == {"$dacsType", "hex"}:
                encoded = value.get("hex")
                if not isinstance(encoded, str) or re.fullmatch(r"(?:[0-9a-f]{2})*", encoded) is None:
                    raise AdapterError("MALFORMED_TAG", "bytes tag requires even-length lowercase hex")
                parent[key] = bytes.fromhex(encoded)
                continue
            if tag == "bigint" and set(value) == {"$dacsType", "decimal"}:
                decimal = value.get("decimal")
                if not isinstance(decimal, str) or re.fullmatch(r"-?(?:0|[1-9][0-9]*)", decimal) is None:
                    raise AdapterError("MALFORMED_TAG", "bigint tag requires canonical decimal text")
                host_type_unsupported = True
                continue
            raise AdapterError("MALFORMED_TAG", f"unsupported or malformed tagged value: {tag!r}")
        if isinstance(value, list):
            parent[key] = value
            for index in range(len(value) - 1, -1, -1):
                stack.append((value, index, value[index]))
        elif isinstance(value, dict):
            parent[key] = value
            for member in reversed(list(value)):
                stack.append((value, member, value[member]))
        else:
            parent[key] = value
    if host_type_unsupported:
        raise AdapterError(
            "UNSUPPORTED_CASE",
            "Python cannot preserve the protocol distinction between a host BigInt and a JSON integer",
        )
    return holder[0]


def _infer_hashable_kind(artifact: Any) -> str:
    if not isinstance(artifact, dict):
        raise AdapterError("UNSUPPORTED_ARTIFACT", "signedScopeHash requires an artifact object")
    discriminators = sorted(TYPE_DISCRIMINATORS.intersection(artifact))
    if len(discriminators) > 1:
        raise AdapterError(
            "UNSUPPORTED_ARTIFACT",
            "signedScopeHash rejects records carrying more than one type discriminator: "
            + ", ".join(discriminators),
        )
    is_evidence = (
        discriminators == ["evidenceVersion"]
        and artifact.get("evidenceVersion") == "1"
        and "jobId" in artifact
        and "phase" in artifact
        and "outcome" in artifact
        and "signature" in artifact
    )
    is_bundle = (
        discriminators == ["bundleVersion"]
        and artifact.get("bundleVersion") == "1"
        and "jobId" in artifact
        and "outcome" in artifact
        and "phaseSummary" in artifact
        and "signatures" in artifact
    )
    if is_evidence:
        return "SettlementEvidence"
    if is_bundle:
        return "AttestationBundle"
    raise AdapterError(
        "UNSUPPORTED_ARTIFACT",
        "signedScopeHash supports only unambiguous version 1 SettlementEvidence and AttestationBundle shapes",
    )


def _metadata() -> dict[str, Any]:
    adapter = _RELEASE["adapter"]
    wrapped = adapter["wrappedStandard"]
    return {
        "name": adapter["name"],
        "version": adapter["version"],
        "repository": adapter["repository"],
        "observedOrigin": _OBSERVED_ORIGIN,
        "revision": "sha256:" + adapter["source"]["sha256"],
        "provenanceCodebase": adapter["provenanceCodebase"],
        "supportedFamilies": [
            "canonical-accept",
            "canonical-reject",
            "drift-signed-scope",
            "sig-value-encoding",
        ],
        "operations": list(OPERATIONS),
        "boundedOperationProfiles": {
            "domainSepSign": "listing-single-hash-golden-v1",
            "domainSepVerify": "listing-single-hash-golden-v1",
        },
        "wrappedStandard": {
            "revision": wrapped["revision"],
            "tree": wrapped["tree"],
            "primitiveSha256": {
                item["path"]: item["sha256"] for item in wrapped["primitives"]
            },
        },
        "limitations": adapter["limitations"],
    }


def _intermediate_hash_supplied(params: list[Any], position: int, operation: str) -> bool:
    """Report whether the optional intermediate hash is present.

    The shared runner encodes an omitted optional argument as a trailing JSON
    null, so null means absent rather than an unsupported intermediate hash.
    """

    if len(params) == position or params[position] is None:
        return False
    if not isinstance(params[position], bytes):
        raise AdapterError("INVALID_PARAMS", f"{operation} intermediate hash must be a byte tag or null")
    return True


def _execute(operation: str, params: list[Any]) -> Any:
    if operation == "canonicalize":
        if len(params) != 1:
            raise AdapterError("INVALID_PARAMS", "canonicalize requires exactly one parameter")
        return {"hex": _jcs.canonicalize(params[0]).encode("utf-8").hex()}
    if operation == "signedScopeHash":
        if len(params) != 1:
            raise AdapterError("INVALID_PARAMS", "signedScopeHash requires exactly one parameter")
        artifact = params[0]
        return {"hex": _artifact_hash_hex(_infer_hashable_kind(artifact), artifact)}
    if operation == "signatureValueVerdict":
        if len(params) != 1:
            raise AdapterError(
                "INVALID_PARAMS", "signatureValueVerdict requires exactly one parameter"
            )
        try:
            _decode_signature_value(params[0], legacy_allowed=False)
        except (TypeError, ValueError):
            return "REJECT"
        return "ACCEPT"
    if operation == "domainSepSign":
        if len(params) not in {3, 4}:
            raise AdapterError("INVALID_PARAMS", "domainSepSign requires three or four parameters")
        message, separator, private_seed = params[:3]
        if not isinstance(separator, str):
            raise AdapterError("INVALID_PARAMS", "domainSepSign separator must be a string")
        if not isinstance(message, bytes) or not isinstance(private_seed, bytes):
            raise AdapterError(
                "INVALID_PARAMS", "domainSepSign message and private key must be byte tags"
            )
        if len(private_seed) != 32:
            raise AdapterError("INVALID_PARAMS", "domainSepSign private key must be 32 raw bytes")
        if _intermediate_hash_supplied(params, 3, operation):
            raise AdapterError(
                "UNSUPPORTED_CASE", "the bounded Listing signing profile has no intermediate hash"
            )
        if separator != BOUNDED_F5_SEPARATOR:
            raise AdapterError(
                "UNSUPPORTED_CASE", "the bounded signing profile emits only dacs-listing:v1:"
            )
        if re.fullmatch(rb"[0-9a-f]{64}", message) is None:
            raise AdapterError(
                "UNSUPPORTED_CASE",
                "the bounded signing profile requires an ASCII lowercase-hex sha256 message",
            )
        payload = separator.encode("utf-8") + message
        return {"hex": _sign_ed25519(private_seed, payload).hex()}
    if operation == "domainSepVerify":
        if len(params) not in {4, 5}:
            raise AdapterError("INVALID_PARAMS", "domainSepVerify requires four or five parameters")
        message, separator, signature, public_key = params[:4]
        if not isinstance(separator, str):
            raise AdapterError("INVALID_PARAMS", "domainSepVerify separator must be a string")
        if not all(isinstance(value, bytes) for value in (message, signature, public_key)):
            raise AdapterError(
                "INVALID_PARAMS", "domainSepVerify message, signature, and public key must be byte tags"
            )
        if _intermediate_hash_supplied(params, 4, operation):
            raise AdapterError(
                "UNSUPPORTED_CASE", "the bounded Listing verification profile has no intermediate hash"
            )
        if separator != BOUNDED_F5_SEPARATOR:
            if DACS_SEPARATOR_SHAPE.fullmatch(separator):
                raise AdapterError(
                    "UNSUPPORTED_CASE", "the bounded verification profile selects only dacs-listing:v1:"
                )
            return False
        if re.fullmatch(rb"[0-9a-f]{64}", message) is None:
            raise AdapterError(
                "UNSUPPORTED_CASE",
                "the bounded verification profile requires an ASCII lowercase-hex sha256 message",
            )
        payload = separator.encode("utf-8") + message
        return _verify_ed25519(public_key, signature, payload)
    raise AdapterError(
        "UNSUPPORTED_OPERATION",
        f"operation {operation!r} is not advertised by this adapter release",
    )


def _handle(request: Any) -> tuple[str | None, Any]:
    if not isinstance(request, dict):
        raise AdapterError("INVALID_REQUEST", "request must be a JSON object")
    request_id = request.get("id")
    if not _safe_request_id(request_id):
        raise AdapterError(
            "INVALID_REQUEST", "request id must be a bounded UTF-8 string without control characters"
        )
    if request.get("protocol") != PROTOCOL:
        raise AdapterError("PROTOCOL_MISMATCH", f"expected protocol {PROTOCOL!r}")
    request_type = request.get("type")
    if request_type == "metadata":
        if set(request) - {"protocol", "id", "type"}:
            raise AdapterError("INVALID_REQUEST", "metadata request has unexpected members")
        return request_id, _metadata()
    if request_type != "execute":
        raise AdapterError("INVALID_REQUEST", "request type must be metadata or execute")
    if set(request) - {"protocol", "id", "type", "operation", "params"}:
        raise AdapterError("INVALID_REQUEST", "execute request has unexpected members")
    operation = request.get("operation")
    params = request.get("params")
    if not isinstance(operation, str) or not operation:
        raise AdapterError("INVALID_REQUEST", "execute operation must be a non-empty string")
    if not isinstance(params, list) or len(params) > MAX_PARAMS:
        raise AdapterError("INVALID_REQUEST", "execute params must be a bounded array")
    if operation not in OPERATIONS:
        raise AdapterError(
            "UNSUPPORTED_OPERATION",
            f"operation {operation!r} is not advertised by this adapter release",
        )
    return request_id, _execute(operation, _decode_tagged(params))


def _safe_request_id(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > MAX_REQUEST_ID_CHARS:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return not any(unicodedata.category(character) == "Cc" for character in value)


def _reject_json_constant(name: str) -> None:
    raise ValueError(f"{name} is not a JSON value")


def _parse_request(line: bytes) -> Any:
    """Parse one strict UTF-8 JSON request; any decoding failure is INVALID_JSON."""

    try:
        return json.loads(line.decode("utf-8"), parse_constant=_reject_json_constant)
    except (ValueError, RecursionError) as exc:
        raise AdapterError("INVALID_JSON", _clean_message(exc)) from exc


def _response(request_id: str | None, *, result: Any = None, error: AdapterError | None = None) -> bytes:
    envelope: dict[str, Any] = {"protocol": PROTOCOL, "id": request_id}
    if error is None:
        envelope.update({"ok": True, "result": result})
    else:
        envelope.update(
            {
                "ok": False,
                "error": {"code": error.code, "message": _clean_message(error)},
            }
        )
    return (json.dumps(envelope, ensure_ascii=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _discard_line_tail(stream: Any) -> None:
    while True:
        chunk = stream.readline(MAX_REQUEST_BYTES + 1)
        if not chunk or chunk.endswith(b"\n"):
            return


def main() -> int:
    incoming = sys.stdin.buffer
    outgoing = sys.stdout.buffer
    while True:
        line = incoming.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            return 0
        request_id: str | None = None
        if len(line) > MAX_REQUEST_BYTES:
            if not line.endswith(b"\n"):
                _discard_line_tail(incoming)
            error = AdapterError("REQUEST_TOO_LARGE", "request exceeds 1048576 bytes")
            _stderr(f"dacs-adapter: {error.code}: {error}")
            outgoing.write(_response(None, error=error))
            outgoing.flush()
            continue
        try:
            request = _parse_request(line)
            if isinstance(request, dict) and _safe_request_id(request.get("id")):
                request_id = request["id"][:MAX_REQUEST_ID_CHARS]
            request_id, result = _handle(request)
            outgoing.write(_response(request_id, result=result))
        except AdapterError as exc:
            _stderr(
                f"dacs-adapter: request {request_id or '<unknown>'}: {exc.code}: {_clean_message(exc)}"
            )
            outgoing.write(_response(request_id, error=exc))
        except Exception as exc:  # fail closed at the subprocess boundary
            error = AdapterError("OPERATION_FAILED", _clean_message(exc))
            _stderr(f"dacs-adapter: request {request_id or '<unknown>'}: {error.code}: {error}")
            outgoing.write(_response(request_id, error=error))
        outgoing.flush()


if __name__ == "__main__":
    raise SystemExit(main())
