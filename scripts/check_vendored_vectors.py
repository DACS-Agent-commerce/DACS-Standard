#!/usr/bin/env python3
"""Report drift between vendored copies of the conformance vector sets and this repository.

An implementation that copies this repository's vector sets into its own tree
can run this checker to see which copies no longer match:

    python3 scripts/check_vendored_vectors.py path/to/vendored/vectors
    python3 scripts/check_vendored_vectors.py path/to/vendored/vectors --rev v0.4
    python3 scripts/check_vendored_vectors.py path/to/vendored/vectors --json

A vector set is a JSON object with ``set``, ``spec``, ``count``, ``hash`` and
``vectors`` members, such as the files under ``conformance/vectors/security/``.
Sets are found recursively under ``conformance/vectors/`` in the Standard
checkout (its working tree, or ``--rev``) and under the vendored directory,
and are matched by their ``set`` name, so the vendored layout may be flat or
keep the ``security/`` subdirectory. Other JSON files are counted as ignored.
An object with any required set member must have all five members.

Each set is reported as ``match``, ``drifted``, ``missing`` (in the Standard,
not vendored), ``extra`` (vendored, not in the Standard), or ``uncheckable``
when neither supported content hash is available. Missing/extra status is
retained independently of hash availability. A matched set has drifted when
any of these differ:

- ``vectors``: sha256(canonical_json(vectors)) on each side, using
  ``validate_conformance_vectors.canonical_json``, plus exact, type-strict
  parsed JSON equality. This also detects Unicode normalization and integral
  float changes that canonicalization hides. ``canonical_json`` refuses some
  values on purpose, such as integers outside the CORE §B.2 safe range.
  On refusal, use a declared-encoding hash verified with the encodings accepted
  by ``validate_security_vectors``. The report labels that comparison mode.
  Numbers compare as parsed Python values, preserving int/float types; numeric
  spelling and precision lost during parsing are not compared. Canonical
  hashing ignores member order; the fallback must reproduce a declared hash
  under a validator-accepted encoding;
- ``count``: the vendored ``count`` differs from the Standard's, or from the
  vendored ``vectors`` length;
- ``hash``: the vendored declared ``hash`` differs from the Standard's;
- ``spec``: the vendored ``spec`` string, which names the specification
  sections and revision the set covers, differs from the Standard's.

Exit status: 0 when every set matches, 1 when any set is drifted, missing or
extra, 2 on any uncheckable set or bad input (unreadable paths or revision,
symlinked subdirectories,
invalid or excessively nested JSON, a set file missing a required member,
or two files declaring the same set). Exit 2 takes precedence over drift.

Dependency-free stdlib, matching the other validators.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_conformance_vectors import canonical_json  # noqa: E402
from validate_security_vectors import canonical_encodings  # noqa: E402

VECTORS_DIR = "conformance/vectors"
REQUIRED_MEMBERS = {"set": str, "spec": str, "count": int, "hash": str, "vectors": list}
HASH_RULE = "sha256(canonical_json(vectors))"


class BadInput(Exception):
    """Input the checker cannot evaluate; reported with exit status 2."""


@dataclass
class VectorSet:
    name: str
    path: str
    spec: str
    count: int
    declared_hash: str
    vectors: list[Any]
    content_hash: str | None
    hash_error: str | None
    encoded_hashes: dict[str, str]
    declared_encodings: list[str]

    @property
    def uncheckable(self) -> bool:
        return self.content_hash is None and not self.declared_encodings


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate object member {name!r}")
        result[name] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def parse_set(raw: bytes, label: str) -> VectorSet | None:
    """Parse one JSON file strictly; return None when it is not a vector set."""
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_members,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError) as exc:
        raise BadInput(f"{label}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict) or not REQUIRED_MEMBERS.keys() & data.keys():
        return None
    for member, kind in REQUIRED_MEMBERS.items():
        value = data.get(member)
        if not isinstance(value, kind) or isinstance(value, bool):
            raise BadInput(f"{label}: vector set needs a {kind.__name__} {member!r} member")
    content_hash = hash_error = None
    try:
        content_hash = hashlib.sha256(canonical_json(data["vectors"])).hexdigest()
    except RecursionError as exc:
        raise BadInput(f"{label}: vectors are too deeply nested to hash") from exc
    except (TypeError, ValueError) as exc:
        hash_error = str(exc)
    encoded_hashes = {}
    if content_hash is None:
        try:
            encoded_hashes = {
                encoding: hashlib.sha256(raw).hexdigest()
                for encoding, raw in canonical_encodings(data["vectors"]).items()
            }
        except RecursionError as exc:
            raise BadInput(f"{label}: vectors are too deeply nested to hash") from exc
        except (TypeError, ValueError, UnicodeError):
            pass
    return VectorSet(
        name=data["set"],
        path=label,
        spec=data["spec"],
        count=data["count"],
        declared_hash=data["hash"],
        vectors=data["vectors"],
        content_hash=content_hash,
        hash_error=hash_error,
        encoded_hashes=encoded_hashes,
        declared_encodings=[encoding for encoding, digest in encoded_hashes.items()
                            if digest == data["hash"]],
    )


def index_sets(files: list[tuple[str, bytes]], side: str) -> tuple[dict[str, VectorSet], int]:
    sets: dict[str, VectorSet] = {}
    ignored = 0
    for label, raw in files:
        vector_set = parse_set(raw, f"{side} {label}")
        if vector_set is None:
            ignored += 1
            continue
        vector_set.path = label
        if vector_set.name in sets:
            raise BadInput(
                f"{side}: set {vector_set.name!r} is declared by both "
                f"{sets[vector_set.name].path} and {label}"
            )
        sets[vector_set.name] = vector_set
    return sets, ignored


def read_tree(base: Path) -> list[tuple[str, bytes]]:
    """Every ``*.json`` file under ``base``, as (relative POSIX path, bytes)."""
    if not base.is_dir():
        raise BadInput(f"{base} is not a directory")
    files = []
    def onerror(exc: OSError) -> None:
        raise BadInput(f"cannot walk {base}: {exc}") from exc

    for dirpath, dirnames, filenames in os.walk(base, onerror=onerror):
        dirnames.sort()
        for dirname in dirnames:
            path = Path(dirpath) / dirname
            if path.is_symlink():
                raise BadInput(f"symlinked directory is not supported: {path}")
        for filename in sorted(filenames):
            if not filename.endswith(".json"):
                continue
            path = Path(dirpath) / filename
            try:
                raw = path.read_bytes()
            except OSError as exc:
                raise BadInput(f"cannot read {path}: {exc}") from exc
            files.append((path.relative_to(base).as_posix(), raw))
    return files


def git(standard: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(standard), *args], check=False, capture_output=True
        )
    except OSError as exc:
        raise BadInput(f"cannot run git: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise BadInput(f"git {' '.join(args)} failed in {standard}: {detail}")
    return result.stdout


def read_revision(standard: Path, rev: str) -> tuple[str, list[tuple[str, bytes]]]:
    """Resolve ``rev`` and return its commit and the JSON files under VECTORS_DIR."""
    if not rev or rev.startswith("-"):
        raise BadInput(f"invalid revision {rev!r}")
    try:
        commit = git(standard, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").decode().strip()
    except BadInput as exc:
        raise BadInput(f"unknown revision {rev!r} in {standard} ({exc})") from exc
    names = git(standard, "ls-tree", "-r", "-z", "--name-only", commit, "--", VECTORS_DIR)
    files = []
    for name in sorted(n for n in names.decode("utf-8").split("\0") if n.endswith(".json")):
        raw = git(standard, "cat-file", "blob", f"{commit}:{name}")
        files.append((Path(name).relative_to(VECTORS_DIR).as_posix(), raw))
    return commit, files


def same_json(left: Any, right: Any) -> bool:
    """Parsed-value equality preserving types and float zero signs, not numeric spelling."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same_json(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(same_json(a, b) for a, b in zip(left, right))
    if isinstance(left, float) and left == right == 0:
        return math.copysign(1, left) == math.copysign(1, right)
    return left == right


def compare(standard: VectorSet, vendored: VectorSet) -> dict[str, Any]:
    changes = []
    try:
        exact = same_json(standard.vectors, vendored.vectors)
    except RecursionError as exc:
        raise BadInput(f"set {standard.name!r}: vectors are too deeply nested to compare") from exc
    comparison = "canonical-json-sha256+exact-json"
    note = None
    uncheckable = standard.uncheckable or vendored.uncheckable
    encoding = None
    hashes = {"standard": standard.content_hash, "vendored": vendored.content_hash}
    if standard.content_hash is not None and vendored.content_hash is not None:
        if standard.content_hash != vendored.content_hash or not exact:
            changes.append("vectors")
        if standard.content_hash == vendored.content_hash and not exact:
            note = "equal under canonical_json; differs as exact JSON (Unicode normalization or number form)"
    else:
        note = "; ".join(
            f"{side}: {vector_set.hash_error}"
            for side, vector_set in (("standard", standard), ("vendored", vendored))
            if vector_set.content_hash is None
        )
        if not uncheckable:
            comparison = "declared-encoding-sha256+parsed-json"
            encoding = (standard.declared_encodings or vendored.declared_encodings)[0]
            try:
                hashes = {
                    side: vector_set.encoded_hashes.get(encoding) or hashlib.sha256(
                        canonical_encodings(vector_set.vectors)[encoding]).hexdigest()
                    for side, vector_set in (("standard", standard), ("vendored", vendored))
                }
            except RecursionError as exc:
                raise BadInput(f"set {standard.name!r}: vectors are too deeply nested to hash") from exc
            note = f"canonical_json unavailable ({note}); compared using {encoding}"
        else:
            comparison = "uncheckable"
            note = f"no canonical or verified declared-encoding hash ({note})"
        if not exact:
            changes.append("vectors")
        elif not uncheckable and hashes["standard"] != hashes["vendored"]:
            changes.append("vectors")
    if vendored.count != standard.count or vendored.count != len(vendored.vectors):
        changes.append("count")
    if vendored.declared_hash != standard.declared_hash:
        changes.append("hash")
    if vendored.spec != standard.spec:
        changes.append("spec")
    return {
        "set": standard.name,
        "status": "uncheckable" if uncheckable else ("drifted" if changes else "match"),
        "changes": changes,
        "standardPath": standard.path,
        "vendoredPath": vendored.path,
        "comparison": comparison,
        "comparisonNote": note,
        "uncheckable": uncheckable,
        "hashEncoding": encoding,
        "comparisonHash": hashes,
        "contentHash": {"standard": standard.content_hash, "vendored": vendored.content_hash},
        "count": {
            "standard": standard.count,
            "vendored": vendored.count,
            "vendoredVectors": len(vendored.vectors),
        },
        "hash": {"standard": standard.declared_hash, "vendored": vendored.declared_hash},
        "spec": {"standard": standard.spec, "vendored": vendored.spec},
    }


def one_sided(vector_set: VectorSet, status: str) -> dict[str, Any]:
    side = "standard" if status == "missing" else "vendored"
    result = {"set": vector_set.name, "status": status, f"{side}Path": vector_set.path,
              "spec": vector_set.spec, "uncheckable": vector_set.uncheckable}
    if vector_set.uncheckable:
        result.update(
            comparison="uncheckable",
            comparisonNote=f"{side}: no canonical or verified declared-encoding hash ({vector_set.hash_error})",
        )
    return result


def check(vendored_dir: Path, standard: Path, rev: str | None) -> dict[str, Any]:
    commit = None
    if rev is None:
        standard_files = read_tree(standard / VECTORS_DIR)
    else:
        commit, standard_files = read_revision(standard, rev)
    standard_sets, standard_ignored = index_sets(standard_files, "standard")
    if not standard_sets:
        raise BadInput(f"no vector sets found under {VECTORS_DIR} in the Standard checkout")
    vendored_sets, vendored_ignored = index_sets(read_tree(vendored_dir), "vendored")

    results = []
    for name in sorted(set(standard_sets) | set(vendored_sets)):
        if name not in vendored_sets:
            results.append(one_sided(standard_sets[name], "missing"))
        elif name not in standard_sets:
            results.append(one_sided(vendored_sets[name], "extra"))
        else:
            results.append(compare(standard_sets[name], vendored_sets[name]))
    summary = {"standard": len(standard_sets), "vendored": len(vendored_sets)}
    summary["ignoredJson"] = {"standard": standard_ignored, "vendored": vendored_ignored}
    for status in ("match", "drifted", "missing", "extra"):
        summary[status] = sum(1 for result in results if result["status"] == status)
    summary["uncheckable"] = sum(1 for result in results if result["uncheckable"])
    return {
        "standard": {"path": str(standard), "revision": rev, "commit": commit},
        "vendored": str(vendored_dir),
        "hashRule": HASH_RULE,
        "fallbackHashRule": "sha256(vectors encoded as verified by validate_security_vectors)",
        "drift": any(r["status"] in ("drifted", "missing", "extra") or r.get("changes") for r in results),
        "uncheckable": summary["uncheckable"] > 0,
        "summary": summary,
        "sets": results,
    }


def render_text(report: dict[str, Any]) -> str:
    standard = report["standard"]
    source = "working tree" if standard["revision"] is None else (
        f"revision {standard['revision']} at {standard['commit']}"
    )
    lines = [
        f"Standard: {standard['path']} ({source})",
        f"Vendored: {report['vendored']}",
        "",
    ]
    for result in report["sets"]:
        status = result["status"]
        if status == "match":
            if result["hashEncoding"]:
                lines.append(f"MATCH    {result['set']}  ({result['comparison']}: {result['hashEncoding']})")
            continue
        if status == "missing":
            lines.append(f"MISSING  {result['set']}  (standard {result['standardPath']})")
            if result["uncheckable"]:
                lines.append(f"  hash unavailable: {result['comparisonNote']}")
            continue
        if status == "extra":
            lines.append(f"EXTRA    {result['set']}  (vendored {result['vendoredPath']})")
            if result["uncheckable"]:
                lines.append(f"  hash unavailable: {result['comparisonNote']}")
            continue
        if status == "uncheckable":
            lines.append(f"UNCHECKABLE  {result['set']}  (hash unavailable: {result['comparisonNote']})")
            if result["changes"]:
                lines.append(f"  observed differences: {', '.join(result['changes'])}")
            continue
        lines.append(
            f"DRIFTED  {result['set']}  (standard {result['standardPath']}, "
            f"vendored {result['vendoredPath']})"
        )
        if result["hashEncoding"]:
            lines.append(f"  comparison: {result['comparison']} ({result['hashEncoding']})")
        for change in result["changes"]:
            if change == "vectors":
                hashes = result["comparisonHash"]
                lines.append(
                    f"  vectors: {result['comparison']} standard {hashes['standard']}, "
                    f"vendored {hashes['vendored']}"
                )
                if result["comparisonNote"]:
                    lines.append(f"  vectors: {result['comparisonNote']}")
            elif change == "count":
                count = result["count"]
                lines.append(
                    f"  count: standard {count['standard']}, vendored {count['vendored']} "
                    f"(vendored vectors: {count['vendoredVectors']})"
                )
            elif change == "hash":
                lines.append(
                    f"  hash: standard {result['hash']['standard']}, "
                    f"vendored {result['hash']['vendored']}"
                )
            elif change == "spec":
                lines.append(f"  spec: standard {result['spec']['standard']!r}")
                lines.append(f"        vendored {result['spec']['vendored']!r}")
    summary = report["summary"]
    if len(lines) > 3:
        lines.append("")
    lines.append(
        f"{summary['standard']} standard sets, {summary['vendored']} vendored: "
        f"{summary['match']} match, {summary['drifted']} drifted, "
        f"{summary['missing']} missing, {summary['extra']} extra, {summary['uncheckable']} uncheckable."
    )
    ignored = summary["ignoredJson"]
    lines.append(f"Ignored JSON files: {ignored['standard']} standard, {ignored['vendored']} vendored.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report drift between vendored conformance vector sets and this repository."
    )
    parser.add_argument("vendored", type=Path, help="directory holding the vendored vector sets")
    parser.add_argument(
        "--standard",
        type=Path,
        default=ROOT,
        help="DACS-Standard checkout to compare against (default: this repository)",
    )
    parser.add_argument("--rev", help="compare against this git revision of the checkout")
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    args = parser.parse_args(argv)
    try:
        report = check(args.vendored, args.standard, args.rev)
    except BadInput as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}, indent=2))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2) if args.json else render_text(report))
    if report["uncheckable"]:
        return 2
    return 1 if report["drift"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
