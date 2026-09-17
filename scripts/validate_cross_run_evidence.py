#!/usr/bin/env python3
"""Validate the proposed dacs-cross-run-evidence/1 provenance envelope.

This is an additive, non-normative proposal.  It does not change the legacy
input accepted by ``diff_vector_runs.py``.  A successful validation means the
run names an exact corpus artifact and immutable revisions; it does not prove
implementation independence, execute an adapter, or promote a vector set.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "dacs-cross-run-evidence/1"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
SAFE_SET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
REGULAR_FILE_MODES = {"100644", "100755"}


class EvidenceError(ValueError):
    pass


def _git(checkout: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(checkout), *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise EvidenceError(f"git {' '.join(args)} failed in {checkout}: {detail}")
    return result.stdout


def _origin(checkout: Path) -> str:
    return _git(checkout, "remote", "get-url", "origin").decode().strip()


def _same_repository(left: str, right: str) -> bool:
    """Allow only the equivalent HTTPS spelling with or without `.git`/`/`."""
    def normalize(value: str) -> str:
        value = value.rstrip("/")
        return value[:-4] if value.endswith(".git") else value

    return normalize(left) == normalize(right)


def _string(obj: dict[str, Any], field: str, where: str) -> str:
    value = obj.get(field)
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"{where}.{field} must be a non-empty string")
    return value


def _revision(obj: dict[str, Any], where: str) -> str:
    revision = _string(obj, "revision", where)
    if not HEX40.fullmatch(revision):
        raise EvidenceError(f"{where}.revision must be a full lowercase 40-hex commit id")
    return revision


def _safe_path(value: str, where: str) -> str:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise EvidenceError(f"{where}.path must be a repository-relative path")
    return path.as_posix()


def _expected_corpus_path(checkout: Path, set_name: str) -> str:
    if not SAFE_SET.fullmatch(set_name):
        raise EvidenceError("evidence.set must be a single safe filename stem")
    candidates = (
        f"conformance/vectors/security/{set_name}.json",
        f"conformance/fixtures/identity/{set_name}.json",
    )
    present = [
        path
        for path in candidates
        if (checkout / path).is_file() and not (checkout / path).is_symlink()
    ]
    if len(present) != 1:
        raise EvidenceError(
            f"set '{set_name}' must resolve to exactly one trusted corpus path; "
            f"found {len(present)}"
        )
    return present[0]


def _verify_commit(checkout: Path, revision: str, where: str) -> None:
    actual = _git(checkout, "rev-parse", f"{revision}^{{commit}}").decode().strip()
    if actual != revision:
        raise EvidenceError(f"{where}.revision did not resolve to the recorded commit")


def _verify_repository(
    obj: dict[str, Any], checkout: Path, where: str, *, artifact: bool
) -> None:
    repository = _string(obj, "repository", where)
    actual_origin = _origin(checkout)
    if not _same_repository(repository, actual_origin):
        raise EvidenceError(
            f"{where}.repository does not match checkout origin: "
            f"recorded {repository!r}, checkout {actual_origin!r}"
        )
    revision = _revision(obj, where)
    _verify_commit(checkout, revision, where)
    if not artifact:
        return

    path = _safe_path(_string(obj, "path", where), where)
    want_sha256 = _string(obj, "sha256", where)
    want_blob = _string(obj, "gitBlob", where)
    if not HEX64.fullmatch(want_sha256):
        raise EvidenceError(f"{where}.sha256 must be lowercase 64-hex")
    if not HEX40.fullmatch(want_blob):
        raise EvidenceError(f"{where}.gitBlob must be lowercase 40-hex")

    tree_output = _git(checkout, "ls-tree", "-z", revision, "--", path)
    entries = tree_output.split(b"\0")
    if len(entries) != 2 or entries[1] or b"\t" not in entries[0]:
        raise EvidenceError(f"{where}.path does not resolve to one committed entry")
    metadata, resolved_path = entries[0].split(b"\t", 1)
    parts = metadata.decode("ascii").split()
    if len(parts) != 3:
        raise EvidenceError(f"{where}.path has malformed Git tree metadata")
    mode, object_type, actual_blob = parts
    if (
        resolved_path != path.encode("utf-8")
        or mode not in REGULAR_FILE_MODES
        or object_type != "blob"
    ):
        raise EvidenceError(f"{where}.path must resolve to a committed regular file blob")
    committed = _git(checkout, "cat-file", "blob", actual_blob)
    actual_sha256 = hashlib.sha256(committed).hexdigest()
    if want_sha256 != actual_sha256:
        raise EvidenceError(f"{where}.sha256 does not match {revision}:{path}")
    if want_blob != actual_blob:
        raise EvidenceError(f"{where}.gitBlob does not match {revision}:{path}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> Any:
    raise EvidenceError(f"non-finite JSON constant {value!r} is not permitted")


def load_json_strict(text: str) -> Any:
    """Parse JSON without duplicate object keys or non-finite constants."""
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_non_finite,
        )
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid JSON: {exc}") from exc


def validate_evidence(
    evidence: Any,
    *,
    standard_checkout: Path = ROOT,
    runner_checkout: Path | None = None,
    implementation_checkout: Path | None = None,
) -> None:
    if not isinstance(evidence, dict):
        raise EvidenceError("evidence root must be an object")
    if evidence.get("schema") != SCHEMA:
        raise EvidenceError(f"schema must be exactly {SCHEMA!r}")
    set_name = _string(evidence, "set", "evidence")
    impl = _string(evidence, "impl", "evidence")
    results = evidence.get("results")
    if not isinstance(results, list):
        raise EvidenceError("evidence.results must be an array")

    corpus = evidence.get("corpus")
    implementation = evidence.get("implementation")
    runner = evidence.get("runner")
    for value, where in (
        (corpus, "evidence.corpus"),
        (implementation, "evidence.implementation"),
        (runner, "evidence.runner"),
    ):
        if not isinstance(value, dict):
            raise EvidenceError(f"{where} must be an object")

    if _string(implementation, "id", "evidence.implementation") != impl:
        raise EvidenceError("evidence.impl must equal evidence.implementation.id")

    expected_path = _expected_corpus_path(standard_checkout, set_name)
    recorded_path = _safe_path(_string(corpus, "path", "evidence.corpus"), "evidence.corpus")
    if recorded_path != expected_path:
        raise EvidenceError(
            f"evidence.corpus.path must be the trusted path for set '{set_name}': "
            f"{expected_path}"
        )
    _verify_repository(corpus, standard_checkout, "evidence.corpus", artifact=True)

    # Binding to the recorded revision is insufficient if the trusted checkout
    # now resolves the set name to changed bytes.  Compare both so an old run
    # cannot be presented as current after a same-name corpus edit.
    committed = _git(
        standard_checkout,
        "show",
        f"{corpus['revision']}:{recorded_path}",
    )
    current = (standard_checkout / recorded_path).read_bytes()
    if current != committed:
        raise EvidenceError(
            "current trusted corpus bytes differ from the recorded corpus revision; "
            "this run is historical, not current evidence"
        )

    # The immutable coordinates are mandatory even when the corresponding
    # external checkout is unavailable.  Supplying a checkout makes those
    # assertions mechanical as well.
    _string(implementation, "repository", "evidence.implementation")
    _revision(implementation, "evidence.implementation")
    _string(runner, "repository", "evidence.runner")
    _revision(runner, "evidence.runner")
    _safe_path(_string(runner, "path", "evidence.runner"), "evidence.runner")
    for field, pattern in (("sha256", HEX64), ("gitBlob", HEX40)):
        if not pattern.fullmatch(_string(runner, field, "evidence.runner")):
            raise EvidenceError(f"evidence.runner.{field} has invalid lowercase-hex form")
    if implementation_checkout is not None:
        _verify_repository(
            implementation,
            implementation_checkout,
            "evidence.implementation",
            artifact=False,
        )
    if runner_checkout is not None:
        _verify_repository(runner, runner_checkout, "evidence.runner", artifact=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", nargs="+", type=Path)
    parser.add_argument("--standard-checkout", type=Path, default=ROOT)
    parser.add_argument("--runner-checkout", type=Path)
    parser.add_argument("--implementation-checkout", type=Path)
    args = parser.parse_args(argv)

    failed = False
    for path in args.evidence:
        try:
            evidence = load_json_strict(path.read_text(encoding="utf-8"))
            validate_evidence(
                evidence,
                standard_checkout=args.standard_checkout.resolve(),
                runner_checkout=(args.runner_checkout.resolve() if args.runner_checkout else None),
                implementation_checkout=(
                    args.implementation_checkout.resolve()
                    if args.implementation_checkout
                    else None
                ),
            )
        except (OSError, EvidenceError) as exc:
            failed = True
            print(f"INVALID {path}: {exc}", file=sys.stderr)
        else:
            runner_status = (
                "runner checkout verified"
                if args.runner_checkout
                else "runner coordinates recorded but UNVERIFIED"
            )
            implementation_status = (
                "implementation checkout verified"
                if args.implementation_checkout
                else "implementation coordinates recorded but UNVERIFIED"
            )
            print(
                f"VALID {path}: corpus Git binding verified; {runner_status}; "
                f"{implementation_status}"
            )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
