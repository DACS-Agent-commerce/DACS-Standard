#!/usr/bin/env python3
"""Verify the HTLC-9 / ST-8 asymmetric-settlement pack (DACS-4 §9.5.4, §10.3.1).

Two signed ``SettlementEvidence`` fixtures form one supersession pair:

* the interim ``outcome: "failure"`` record (``dest-revealed-source-unclaimed``);
* the ST-8 ``:resolved`` ``outcome: "success"`` record whose
  ``supersedesEvidenceRef.contentHash`` MUST equal the §B.2 content hash of the
  interim record.

This verifier is executable, not a shape check: each record's Ed25519 signature
is verified over ``"dacs-evidence:v1:" || sha256hex(JCS(record minus signature))``
against the ``cci:<pubkey-hex>`` signer, and the supersession hash is recomputed.
No amendment of any kind is accepted — ST-8 resolution is a same-phase
supersession, not a ``correction`` (DACS-4-SETTLE.md: "No ``correction``
amendment is used").

Scope limit, stated rather than papered over: this pack carries no rail context, so
"source chain" is defined by where the ``htlc-lock`` sits. The verifier enforces that the
claim shares the lock's chain and contract and that the reveal is on a different chain.
A pair whose lock/reveal/claim are all consistently mirrored onto the other chain is
therefore indistinguishable from a correct one here; detecting that needs the rail
definition's source/destination declaration (DACS-4 §9.4), which an SR-2 reader has
and this fixture pack does not.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import jcs  # noqa: E402

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover
    raise SystemExit("cryptography is required for signature verification: python3 -m pip install cryptography")

FIXTURE_DIR = ROOT / "conformance" / "fixtures" / "settlement"
DEFAULT_INTERIM = FIXTURE_DIR / "htlc9-asymmetric.json"
DEFAULT_RESOLVED = FIXTURE_DIR / "htlc9-asymmetric-resolved.json"

EVIDENCE_DOMAIN = "dacs-evidence:v1:"
CD1_AMOUNT = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$")
FORBIDDEN_KEYS = {"settlementAmendment", "amendmentType", "amendmentRefs", "amendsEvidenceRef", "refundAmount"}


def fail(path: Path, message: str) -> str:
    try:
        label = path.resolve().relative_to(ROOT)
    except ValueError:
        label = path
    return f"{label}: {message}"


def content_hash_hex(record: dict) -> str:
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    return hashlib.sha256(jcs.canonicalize(unsigned).encode("utf-8")).hexdigest()


HEX64 = re.compile(r"^[0-9a-f]{64}$")
ULID = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")  # CORE B.1: jobId is a ULID (Crockford base32, 128-bit)
ANCHOR_KINDS = {"storage-program", "ipfs", "https"}  # DACS-2 §7.5.2
TXREF_FIELDS = {
    "htlc-lock": {"kind", "chainId", "contractAddress", "lockTxHash"},
    "htlc-reveal": {"kind", "chainId", "contractAddress", "revealTxHash"},
    "htlc-claim": {"kind", "chainId", "contractAddress", "claimTxHash"},
}
TX_HASH = re.compile(r"^0x[0-9a-f]{64}$")
TXREF_HASH_FIELD = {"htlc-lock": "lockTxHash", "htlc-reveal": "revealTxHash", "htlc-claim": "claimTxHash"}


def attestation_ref_errors(value: Any) -> list[str]:
    """DACS-2 §7.5.2 AttestationRef exact wire shape: {anchor:{kind,locator}, contentHash, signer?}."""
    if not isinstance(value, dict):
        return ["MUST be an object"]
    errs: list[str] = []
    unknown = set(value) - {"anchor", "contentHash", "signer"}
    if unknown:
        errs.append("has unknown field(s) " + ", ".join(sorted(unknown)) + " (flat kind/locator is the pre-#308 shape)")
    anchor = value.get("anchor")
    if not isinstance(anchor, dict) or set(anchor) != {"kind", "locator"} \
            or not isinstance(anchor.get("kind"), str) or not isinstance(anchor.get("locator"), str):
        errs.append("anchor MUST be {kind, locator}")
    else:
        if anchor["kind"] not in ANCHOR_KINDS:
            errs.append("anchor.kind MUST be one of storage-program | ipfs | https (DACS-2 §7.5.2)")
        if not anchor["locator"].strip():
            errs.append("anchor.locator MUST be non-empty")
    if "signer" in value and not isinstance(value.get("signer"), str):
        errs.append("signer, when present, MUST be a ClaimReference string")
    if not isinstance(value.get("contentHash"), str) or not HEX64.fullmatch(value["contentHash"]):
        errs.append("contentHash MUST be 64 lowercase hex (no prefix)")
    return errs


def is_canonical_sig6(value: str) -> bool:
    """CORE §B.7 SIG-6: unpadded Base64URL that round-trips exactly."""
    if not value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        return False
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value


def txref_errors(refs: Any, path_label: str) -> list[str]:
    errs: list[str] = []
    if not isinstance(refs, list) or not refs:
        return [f"{path_label}: paymentTxRefs MUST be a non-empty list"]
    for i, ref in enumerate(refs):
        if not isinstance(ref, dict) or ref.get("kind") not in TXREF_HASH_FIELD:
            errs.append(f"{path_label}: paymentTxRefs[{i}] MUST be an htlc-lock / htlc-reveal / htlc-claim txRef"); continue
        extra = set(ref) - TXREF_FIELDS[ref["kind"]]
        if extra:
            errs.append(f"{path_label}: {ref['kind']} txRef carries unknown field(s) {', '.join(sorted(extra))} (ChainTxRef arms are closed)")
        field = TXREF_HASH_FIELD[ref["kind"]]
        if not isinstance(ref.get("chainId"), int) or isinstance(ref.get("chainId"), bool) or ref["chainId"] <= 0:
            errs.append(f"{path_label}: {ref['kind']} chainId MUST be a positive integer")
        if not isinstance(ref.get("contractAddress"), str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", ref["contractAddress"]):
            errs.append(f"{path_label}: {ref['kind']} contractAddress MUST be a 0x-prefixed 20-byte hex address")
        if not isinstance(ref.get(field), str) or not TX_HASH.fullmatch(ref[field]):
            errs.append(f"{path_label}: {ref['kind']} MUST carry {field} as 0x-prefixed 32-byte hex")
    return errs


def verify_signature(record: dict) -> str | None:
    """Return an error string, or None when the Ed25519 signature verifies."""
    sig = record.get("signature")
    if not isinstance(sig, dict):
        return "signature MUST be an object"
    if sig.get("algorithm") != "ed25519":
        return "signature.algorithm MUST be ed25519"
    signer = sig.get("signer")
    if not isinstance(signer, str) or not re.fullmatch(r"cci:[0-9a-f]{64}", signer):
        return "signature.signer MUST be cci:<64 lowercase hex> (Ed25519 public key)"
    value = sig.get("value")
    if not isinstance(value, str) or not is_canonical_sig6(value):
        return "signature.value MUST be canonical SIG-6 unpadded base64url (re-encodes to itself)"
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer.removeprefix("cci:")))
        payload = EVIDENCE_DOMAIN.encode("ascii") + content_hash_hex(record).encode("ascii")
        public.verify(raw, payload)
    except (InvalidSignature, ValueError):
        return "signature does not verify over dacs-evidence:v1: || sha256(JCS(record minus signature))"
    return None


def _walk_keys(obj: Any):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _walk_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_keys(v)


def load_case(path: Path) -> tuple[dict | None, list[str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, [fail(path, "fixture file not found")]
    except json.JSONDecodeError as exc:
        return None, [fail(path, f"invalid JSON: {exc}")]
    errors: list[str] = []
    if data.get("kind") != "SettlementEvidenceCase":
        errors.append(fail(path, f"kind MUST be SettlementEvidenceCase, got {data.get('kind')!r}"))
    evidence = data.get("settlementEvidence")
    if not isinstance(evidence, dict):
        return None, errors + [fail(path, "settlementEvidence MUST be an object")]
    forbidden = FORBIDDEN_KEYS & set(_walk_keys(evidence))
    if forbidden:
        errors.append(fail(path, "ST-8 supersession MUST NOT carry amendment fields: " + ", ".join(sorted(forbidden))))
    if evidence.get("evidenceVersion") != "1":
        errors.append(fail(path, "evidenceVersion MUST be '1'"))
    if evidence.get("phase") != "pay-cross-chain-htlc":
        errors.append(fail(path, "phase MUST be pay-cross-chain-htlc"))
    if not isinstance(evidence.get("jobId"), str) or not ULID.fullmatch(evidence["jobId"]):
        errors.append(fail(path, "jobId MUST be a ULID: 26 Crockford-base32 characters, first in 0-7 (CORE B.1)"))
    if not isinstance(evidence.get("observedAt"), int) or isinstance(evidence.get("observedAt"), bool):
        errors.append(fail(path, "observedAt MUST be an integer unix-ms"))
    sig_err = verify_signature(evidence)
    if sig_err:
        errors.append(fail(path, sig_err))
    return evidence, errors


def txref_kinds(evidence: dict) -> list[str]:
    refs = evidence.get("paymentTxRefs")
    if not isinstance(refs, list):
        return []
    return [r.get("kind") for r in refs if isinstance(r, dict)]


def validate_interim(path: Path) -> tuple[dict | None, list[str]]:
    evidence, errors = load_case(path)
    if evidence is None:
        return None, errors
    if evidence.get("outcome") != "failure":
        errors.append(fail(path, "interim HTLC-9 evidence MUST have outcome failure"))
    if evidence.get("reason") != "dest-revealed-source-unclaimed":
        errors.append(fail(path, "interim evidence MUST carry reason dest-revealed-source-unclaimed"))
    errors += [fail(path, e) for e in txref_errors(evidence.get("paymentTxRefs"), "interim")]
    kinds = txref_kinds(evidence)
    if "htlc-lock" not in kinds:
        errors.append(fail(path, "interim evidence MUST carry the htlc-lock txRef"))
    if "htlc-reveal" not in kinds:
        errors.append(fail(path, "paymentTxRefs MUST include an htlc-reveal txRef proving preimage disclosure"))
    if "htlc-claim" in kinds:
        errors.append(fail(path, "interim evidence MUST NOT carry an htlc-claim (that is the resolved record)"))
    for kind in ("htlc-lock", "htlc-reveal"):
        if kinds.count(kind) > 1:
            errors.append(fail(path, f"interim evidence MUST carry exactly one {kind} txRef"))
    if "settlementFinality" in evidence:
        errors.append(fail(path, "interim failure evidence MUST NOT carry settlementFinality"))
    return evidence, errors


def validate_resolved(path: Path, interim: dict | None) -> list[str]:
    evidence, errors = load_case(path)
    if evidence is None:
        return errors
    if evidence.get("outcome") != "success":
        errors.append(fail(path, "ST-8 resolved evidence MUST have outcome success"))
    errors += [fail(path, e) for e in txref_errors(evidence.get("paymentTxRefs"), "resolved")]
    kinds = txref_kinds(evidence)
    for needed in ("htlc-lock", "htlc-reveal", "htlc-claim"):
        if needed not in kinds:
            errors.append(fail(path, f"resolved evidence MUST carry the {needed} txRef"))
        elif kinds.count(needed) > 1:
            errors.append(fail(path, f"resolved evidence MUST carry exactly one {needed} txRef"))
    refs = [r for r in evidence.get("paymentTxRefs", []) if isinstance(r, dict)]
    lock = next((r for r in refs if r.get("kind") == "htlc-lock"), None)
    reveal = next((r for r in refs if r.get("kind") == "htlc-reveal"), None)
    claim = next((r for r in refs if r.get("kind") == "htlc-claim"), None)
    if lock and reveal and claim and all(isinstance(r.get("chainId"), int) for r in (lock, reveal, claim)):
        # HTLC-9 topology (DACS-4 §9.5.4): the lock and the payee's claim are on the SOURCE chain
        # and contract; the payer's reveal is on the DESTINATION chain. A claim on the destination
        # chain is the payer's reveal mislabelled, which is the mix-up ST-8 exists to forbid.
        if claim["chainId"] != lock["chainId"]:
            errors.append(fail(path, "HTLC topology: htlc-claim MUST be on the source chain (claim.chainId == lock.chainId)"))
        if claim.get("contractAddress") != lock.get("contractAddress"):
            errors.append(fail(path, "HTLC topology: htlc-claim MUST target the source lock contract (claim.contractAddress == lock.contractAddress)"))
        if reveal["chainId"] == lock["chainId"]:
            errors.append(fail(path, "HTLC topology: htlc-reveal MUST be on the destination chain (reveal.chainId != lock.chainId) for pay-cross-chain-htlc"))
    if interim is not None:
        def by_kind(ev, kind):
            return next((r for r in ev.get("paymentTxRefs", []) if isinstance(r, dict) and r.get("kind") == kind), None)
        for kind in ("htlc-lock", "htlc-reveal"):
            a, b = by_kind(interim, kind), by_kind(evidence, kind)
            if a is not None and b is not None and a != b:
                errors.append(fail(path, f"resolved {kind} txRef MUST be identical to the interim record's (same lock/reveal identity across the pair)"))
    fin = evidence.get("settlementFinality")
    if not isinstance(fin, dict) or fin.get("model") != "htlc-reveal":
        errors.append(fail(path, "resolved evidence MUST carry settlementFinality.model == htlc-reveal (PC-6)"))
    elif not isinstance(fin.get("finalityObservedAt"), int) or isinstance(fin.get("finalityObservedAt"), bool):
        errors.append(fail(path, "settlementFinality.finalityObservedAt MUST be an integer unix-ms"))
    amount = evidence.get("paymentAmount")
    if not isinstance(amount, dict) or not isinstance(amount.get("currency"), str) or not amount["currency"].strip():
        errors.append(fail(path, "resolved evidence MUST carry paymentAmount with a non-empty currency (REQUIRED on success-outcome records)"))
    elif not isinstance(amount.get("amount"), str) or not CD1_AMOUNT.fullmatch(amount["amount"]) or amount["amount"] == "0":
        errors.append(fail(path, "paymentAmount.amount MUST be a positive canonical decimal string (CD-1)"))
    ref = evidence.get("supersedesEvidenceRef")
    ref_errs = attestation_ref_errors(ref)
    if ref_errs:
        errors += [fail(path, "supersedesEvidenceRef " + e) for e in ref_errs]
    elif interim is not None:
        expected = content_hash_hex(interim)
        if ref["contentHash"] != expected:
            errors.append(fail(path, "supersedesEvidenceRef.contentHash MUST equal the interim record's §B.2 content hash"))
        if interim.get("jobId") != evidence.get("jobId"):
            errors.append(fail(path, "resolved and interim records MUST share jobId"))
    return errors


def validate_pair(interim_path: Path, resolved_path: Path) -> list[str]:
    interim, errors = validate_interim(interim_path)
    errors += validate_resolved(resolved_path, interim)
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("interim", nargs="?", type=Path, default=DEFAULT_INTERIM)
    parser.add_argument("resolved", nargs="?", type=Path, default=DEFAULT_RESOLVED)
    args = parser.parse_args(argv)
    errors = validate_pair(args.interim, args.resolved)
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        return 1
    print("validated HTLC-9 ST-8 supersession pack: 2 fixture(s), both signatures verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
