#!/usr/bin/env python3
"""Bounded ``dacs-adapter/1`` wrapper over pinned DACS-Standard primitives.

This proposal adapter is non-normative.  It verifies the repository origin and
the committed blobs named by its release descriptor before importing the
existing canonicalisation, signed-scope, or signature helpers.  It performs no
network or substrate operations.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any


PROTOCOL = "dacs-adapter/1"
EXPECTED_ORIGIN = "https://github.com/DACS-Agent-commerce/DACS-Standard.git"
ROOT = Path(__file__).resolve().parents[1]
DESCRIPTOR = ROOT / "conformance" / "interop" / "dacs-adapter-release-proposal-v1.json"
MAX_REQUEST_BYTES = 1_048_576
MAX_REQUEST_ID_CHARS = 256
MAX_PARAMS = 5
MAX_DIAGNOSTIC_CHARS = 320
BOUNDED_F5_SEPARATOR = "dacs-listing:v1:"
DACS_SEPARATOR_SHAPE = re.compile(r"dacs[-a-z0-9]*:v[0-9]+:")


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


def _git(*args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"provenance git check failed: {_clean_message(exc)}") from exc
    return completed.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_committed_path(relative: str, *, expected_sha256: str, expected_blob: str) -> None:
    path = ROOT / relative
    if not path.is_file():
        raise RuntimeError(f"missing provenance-pinned file: {relative}")
    if _sha256(path) != expected_sha256:
        raise RuntimeError(f"sha256 mismatch for provenance-pinned file: {relative}")
    if _git("hash-object", "--", relative) != expected_blob:
        raise RuntimeError(f"working blob mismatch for provenance-pinned file: {relative}")
    if _git("rev-parse", f"HEAD:{relative}") != expected_blob:
        raise RuntimeError(f"file is not the expected committed HEAD blob: {relative}")


def _verify_provenance() -> tuple[dict[str, Any], str]:
    try:
        descriptor = json.loads(DESCRIPTOR.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read adapter release descriptor: {_clean_message(exc)}") from exc

    if descriptor.get("schema") != "dacs-adapter-release-proposal/1":
        raise RuntimeError("unexpected adapter release descriptor schema")
    if descriptor.get("protocol", {}).get("id") != PROTOCOL:
        raise RuntimeError("adapter descriptor protocol mismatch")
    observed_origin = _git("config", "--get", "remote.origin.url")
    if observed_origin not in {EXPECTED_ORIGIN, EXPECTED_ORIGIN.removesuffix(".git")}:
        raise RuntimeError("repository origin does not match the pinned DACS-Standard origin")

    wrapped = descriptor.get("adapter", {}).get("wrappedStandard", {})
    revision = wrapped.get("revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise RuntimeError("wrapped Standard revision is not an immutable commit id")
    if _git("rev-parse", f"{revision}^{{commit}}") != revision:
        raise RuntimeError("wrapped Standard revision does not resolve to its pinned commit")
    if _git("rev-parse", f"{revision}^{{tree}}") != wrapped.get("tree"):
        raise RuntimeError("wrapped Standard tree does not match the release descriptor")

    primitives = wrapped.get("primitives")
    if not isinstance(primitives, list) or not primitives:
        raise RuntimeError("adapter descriptor has no wrapped primitives")
    for primitive in primitives:
        relative = primitive.get("path")
        if not isinstance(relative, str):
            raise RuntimeError("wrapped primitive path is malformed")
        if _git("rev-parse", f"{revision}:{relative}") != primitive.get("gitBlob"):
            raise RuntimeError(f"wrapped revision blob mismatch for {relative}")
        _verify_committed_path(
            relative,
            expected_sha256=primitive.get("sha256", ""),
            expected_blob=primitive.get("gitBlob", ""),
        )

    source = descriptor.get("adapter", {}).get("source", {})
    _verify_committed_path(
        source.get("path", ""),
        expected_sha256=source.get("sha256", ""),
        expected_blob=source.get("gitBlob", ""),
    )
    descriptor_relative = str(DESCRIPTOR.relative_to(ROOT))
    if _git("hash-object", "--", descriptor_relative) != _git(
        "rev-parse", f"HEAD:{descriptor_relative}"
    ):
        raise RuntimeError("adapter release descriptor is not committed at HEAD")
    return descriptor, observed_origin


# Provenance checks intentionally precede imports of the wrapped implementation.
try:
    _RELEASE, _OBSERVED_ORIGIN = _verify_provenance()
except RuntimeError as exc:
    if __name__ == "__main__":
        print(f"dacs-adapter: unavailable: {_clean_message(exc)}", file=sys.stderr)
        raise SystemExit(1)
    raise
sys.path.insert(0, str(ROOT / "scripts"))
import jcs as _jcs  # noqa: E402
from run_lifecycle_walkthrough import sign_ed25519 as _sign_ed25519  # noqa: E402,F401
from run_lifecycle_walkthrough import verify_ed25519 as _verify_ed25519  # noqa: E402,F401
from validate_conformance_vectors import artifact_hash_hex as _artifact_hash_hex  # noqa: E402
from validate_conformance_vectors import decode_signature_value as _decode_signature_value  # noqa: E402


def _decode_tagged(root: Any) -> Any:
    """Decode byte tags and abstain when Python cannot preserve a host type."""

    holder: list[Any] = [root]
    stack: list[tuple[Any, Any, Any]] = [(holder, 0, root)]
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
                raise AdapterError(
                    "UNSUPPORTED_CASE",
                    "Python cannot preserve the protocol distinction between a host BigInt and a JSON integer",
                )
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
    return holder[0]


def _infer_hashable_kind(artifact: Any) -> str:
    if not isinstance(artifact, dict):
        raise AdapterError("UNSUPPORTED_ARTIFACT", "signedScopeHash requires an artifact object")
    has_evidence_discriminator = "evidenceVersion" in artifact
    has_bundle_discriminator = "bundleVersion" in artifact
    if has_evidence_discriminator and has_bundle_discriminator:
        raise AdapterError(
            "UNSUPPORTED_ARTIFACT",
            "signedScopeHash rejects mixed evidenceVersion and bundleVersion discriminators",
        )
    is_evidence = (
        artifact.get("evidenceVersion") == "1"
        and "jobId" in artifact
        and "phase" in artifact
        and "outcome" in artifact
        and "signature" in artifact
    )
    is_bundle = (
        artifact.get("bundleVersion") == "1"
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
        "provenanceCodebase": "github.com/DACS-Agent-commerce/DACS-Standard",
        "supportedFamilies": [
            "canonical-accept",
            "canonical-reject",
            "drift-signed-scope",
            "sig-value-encoding",
        ],
        "operations": [
            "canonicalize",
            "signedScopeHash",
            "signatureValueVerdict",
            "domainSepSign",
            "domainSepVerify",
        ],
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
        if len(params) == 4:
            raise AdapterError(
                "UNSUPPORTED_CASE", "the bounded Listing signing profile has no intermediate hash"
            )
        if separator != BOUNDED_F5_SEPARATOR:
            raise AdapterError(
                "UNSUPPORTED_CASE", "the bounded signing profile emits only dacs-listing:v1:"
            )
        if not isinstance(message, bytes) or re.fullmatch(rb"[0-9a-f]{64}", message) is None:
            raise AdapterError(
                "UNSUPPORTED_CASE",
                "the bounded signing profile requires an ASCII lowercase-hex sha256 message",
            )
        if not isinstance(private_seed, bytes) or len(private_seed) != 32:
            raise AdapterError("INVALID_PARAMS", "domainSepSign private key must be 32 raw bytes")
        payload = separator.encode("utf-8") + message
        return {"hex": _sign_ed25519(private_seed, payload).hex()}
    if operation == "domainSepVerify":
        if len(params) not in {4, 5}:
            raise AdapterError("INVALID_PARAMS", "domainSepVerify requires four or five parameters")
        message, separator, signature, public_key = params[:4]
        if len(params) == 5:
            raise AdapterError(
                "UNSUPPORTED_CASE", "the bounded Listing verification profile has no intermediate hash"
            )
        if not isinstance(separator, str):
            raise AdapterError("INVALID_PARAMS", "domainSepVerify separator must be a string")
        if separator != BOUNDED_F5_SEPARATOR:
            if DACS_SEPARATOR_SHAPE.fullmatch(separator):
                raise AdapterError(
                    "UNSUPPORTED_CASE", "the bounded verification profile selects only dacs-listing:v1:"
                )
            return False
        if not all(isinstance(value, bytes) for value in (message, signature, public_key)):
            raise AdapterError(
                "INVALID_PARAMS", "domainSepVerify message, signature, and public key must be byte tags"
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
    return request_id, _execute(operation, _decode_tagged(params))


def _safe_request_id(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > MAX_REQUEST_ID_CHARS:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return not any(unicodedata.category(character) == "Cc" for character in value)


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
            print(f"dacs-adapter: {error.code}: {error}", file=sys.stderr, flush=True)
            outgoing.write(_response(None, error=error))
            outgoing.flush()
            continue
        try:
            request = json.loads(line)
            if isinstance(request, dict) and _safe_request_id(request.get("id")):
                request_id = request["id"][:MAX_REQUEST_ID_CHARS]
            request_id, result = _handle(request)
            outgoing.write(_response(request_id, result=result))
        except AdapterError as exc:
            print(
                f"dacs-adapter: request {request_id or '<unknown>'}: {exc.code}: {_clean_message(exc)}",
                file=sys.stderr,
                flush=True,
            )
            outgoing.write(_response(request_id, error=exc))
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
            error = AdapterError("INVALID_JSON", _clean_message(exc))
            print(
                f"dacs-adapter: request {request_id or '<unknown>'}: {error.code}: {error}",
                file=sys.stderr,
                flush=True,
            )
            outgoing.write(_response(request_id, error=error))
        except Exception as exc:  # fail closed at the subprocess boundary
            error = AdapterError("OPERATION_FAILED", _clean_message(exc))
            print(
                f"dacs-adapter: request {request_id or '<unknown>'}: {error.code}: {error}",
                file=sys.stderr,
                flush=True,
            )
            outgoing.write(_response(request_id, error=error))
        outgoing.flush()


if __name__ == "__main__":
    raise SystemExit(main())
