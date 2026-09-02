#!/usr/bin/env python3
"""Validate that conformance-vector artifacts conform to their spec type shape.

The lifecycle vectors (`conformance/vectors/dacs-v0.1-*.json`) carry, per stage,
an `artifact` of a declared `kind` (e.g. "SettlementEvidence"); the
`conformance/vectors/examples/*.json` files each carry one such `{kind, artifact}`.
Nothing previously checked that those artifacts actually have the FIELDS the
current spec defines for that kind — so when the v0.1 reset reshaped the
artifacts, the hand-authored vectors kept pre-v0.1 shapes (e.g. a
SettlementEvidence with `amount`/`asset`/`chainId` instead of
`phase`/`outcome`/`paymentAmount`) and CI stayed green, because the existing
checks only validate the wrapper + content hash, not the artifact (finding D2,
#133).

This validator derives, directly from the spec's `type X = { ... }` blocks
(single source of truth — no second schema encoding to drift):

  - each artifact's top-level field set, and checks every vector/example
    artifact of that kind: every REQUIRED field present, no UNKNOWN field; and
  - nested `ClaimReference`, exact `AttestationRef`, and the discriminated
    `ChainTxRef` union. A verifier
    emitting `party: {scheme, identifier}`, legacy `{kind,id,contentHash}`
    attestation references, or legacy `{rail,txHash,kind}` transaction
    references produces signed bytes that disagree with the specification even
    when the outer artifact shape looks correct (#145, #308).

It is a *shape* check, not a full semantic verifier. Literal/value checks are
limited to the discriminators needed to select a `ChainTxRef` arm and the
inline `AttestationRef.anchor` shape. Stdlib-only; runs from a clean clone.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC_DIR = ROOT / "spec"
VECTOR_DIR = ROOT / "conformance" / "vectors"
REFERENCE_SHAPE_VECTOR = VECTOR_DIR / "security" / "artifact-reference-shapes-v0.1.json"

# Shared golden fixtures that carry the reference-bearing DACS-4/DACS-5
# artifacts covered by #308. They are not five-stage vector wrappers, so they
# need explicit embedded-artifact discovery.
REFERENCE_FIXTURES = (
    ROOT / "conformance" / "fixtures" / "attestation-bundle-0004.json",
    ROOT / "conformance" / "fixtures" / "attestation-bundle-0004-seller.json",
    ROOT / "conformance" / "fixtures" / "attestation-bundle-htlc9.json",
    ROOT / "conformance" / "fixtures" / "session-bundle-one-sided.json",
    ROOT / "conformance" / "fixtures" / "session-bundles-presence.json",
    ROOT / "conformance" / "fixtures" / "session-bundles-reputation.json",
    ROOT / "conformance" / "fixtures" / "identity" / "dacs1-vet-golden-inputs-v0.1.json",
    ROOT / "conformance" / "fixtures" / "settlement-evidence-payment-success.json",
    ROOT / "conformance" / "fixtures" / "settlement-evidence-delivery-success.json",
    ROOT / "conformance" / "fixtures" / "settlement" / "htlc9-asymmetric.json",
    ROOT / "conformance" / "vectors" / "security" / "bundle-binding-v0.1.json",
)

# Vectors whose artifacts are known-stale (pre-v0.1 shapes) and are awaiting
# regeneration from a reference verifier (finding D2, #133). They are skipped
# with a LOUD notice rather than silently — the gap is disclosed, not hidden —
# so the shape check guards every other (and every future) vector meanwhile.
# Remove an entry the moment its vector is regenerated to conformant shapes.
QUARANTINE: dict[str, str] = {}  # #133 lifted: lifecycle vectors regenerated to current v0.1 spec shapes (pathos-dacs-ref)

_TYPE_OPEN = re.compile(r"^type\s+([A-Za-z_]\w*)\s*=\s*\{")
_FIELD = re.compile(r"^\s*([A-Za-z_]\w*)(\??)\s*:\s*(.*)$")

_ATTESTATION_ANCHOR_KINDS = {"storage-program", "ipfs", "https"}

# DACS-4 §9.3 is a multi-line discriminated union rather than a `type X = {`
# block, so the generic type-block parser cannot derive its arms. Keep the
# closed arm field sets here and pin them against an executable vector set.
_CHAIN_TX_REF_ARMS: dict[str, tuple[set[str], set[str]]] = {
    "evm": ({"kind", "chainId", "txHash"}, set()),
    "evm-event": ({"kind", "chainId", "txHash", "logIndex"}, set()),
    "solana": ({"kind", "cluster", "signature"}, set()),
    "solana-instruction": (
        {"kind", "cluster", "signature", "instructionIndex"}, set()
    ),
    "demos": ({"kind", "txHash"}, {"blockNumber"}),
    "storage-program": ({"kind", "address", "writeTxHash"}, set()),
    "ap2": ({"kind", "mandateId", "providerRef", "protocolVersion"}, {"receiptAttestation"}),
    "x402": (
        {"kind", "httpResource", "paymentReceiptHash", "protocolVersion"},
        {"settlementTxHash", "chainId"},
    ),
    "x402-event": (
        {
            "kind", "httpResource", "paymentReceiptHash", "settlementTxHash",
            "chainId", "logIndex", "protocolVersion",
        },
        set(),
    ),
    "htlc-lock": ({"kind", "chainId", "contractAddress", "lockTxHash"}, set()),
    "htlc-reveal": ({"kind", "chainId", "contractAddress", "revealTxHash"}, set()),
    "htlc-claim": ({"kind", "chainId", "contractAddress", "claimTxHash"}, set()),
    "htlc-refund": ({"kind", "chainId", "contractAddress", "refundTxHash"}, set()),
    "liquidity-tank": (
        {"kind", "bridgeId", "sourceChainId", "destChainId", "lockTxHash"},
        {"releaseTxHash", "recoveryDeadline"},
    ),
}


def _strip_comment(line: str) -> str:
    i = line.find("//")
    return line[:i] if i >= 0 else line


def parse_type_fields(text: str) -> dict[str, dict]:
    """Map each `type X = {...}` to its top-level field info.

    Per type: `required` / `optional` (field-name sets) and `ftypes`
    (field name → declared type string, comment-stripped). Brace depth is
    tracked so only depth-1 fields are read; fields inside a nested object are
    ignored, and the block ends when the matching close brace returns depth to 0.
    Nested object types are captured from their own `type` blocks.
    """
    out: dict[str, dict] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = _TYPE_OPEN.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        required: set[str] = set()
        optional: set[str] = set()
        ftypes: dict[str, str] = {}
        depth = lines[i].count("{") - lines[i].count("}")  # usually 1
        i += 1
        while i < len(lines) and depth > 0:
            code = _strip_comment(lines[i])
            if depth == 1:
                fm = _FIELD.match(code)
                if fm:
                    fname, opt, ftype = fm.group(1), fm.group(2), fm.group(3).strip()
                    (optional if opt else required).add(fname)
                    if ftype:
                        ftypes[fname] = ftype
            depth += code.count("{") - code.count("}")
            i += 1
        out[name] = {"required": required, "optional": optional, "ftypes": ftypes}
    return out


def collect_type_fields() -> dict[str, dict]:
    types: dict[str, dict] = {}
    for md in sorted(SPEC_DIR.glob("*.md")):
        for name, fields in parse_type_fields(md.read_text(encoding="utf-8")).items():
            types[name] = fields
    return types


def _base_and_array(ftype: str) -> tuple[str, bool]:
    """('ClaimReference[]' -> ('ClaimReference', True)); a union / inline-object
    type returns itself with array=False (it won't match a known type name)."""
    t = ftype.strip()
    is_arr = t.endswith("[]")
    if is_arr:
        t = t[:-2].strip()
    return t, is_arr


def _check_field_set(body: dict, typename: str, spec: dict, ctx: str,
                     errors: list[str], path: str = "") -> None:
    present = set(body)
    missing = spec["required"] - present
    unknown = present - spec["required"] - spec["optional"]
    label = f"`{path}` ({typename})" if path else typename
    if missing:
        errors.append(f"{ctx}: {label} missing required field(s): {sorted(missing)}")
    if unknown:
        errors.append(f"{ctx}: {label} has unknown field(s): {sorted(unknown)}")


def check_attestation_ref(value, ctx: str, errors: list[str], path: str) -> None:
    """Validate the exact DACS-2 §7.5.2 AttestationRef wire shape."""
    if not isinstance(value, dict):
        errors.append(f"{ctx}: `{path}` is an AttestationRef and MUST be an object")
        return
    required = {"anchor", "contentHash"}
    optional = {"signer"}
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing:
        errors.append(f"{ctx}: `{path}` AttestationRef missing required field(s): {sorted(missing)}")
    if unknown:
        errors.append(f"{ctx}: `{path}` AttestationRef has unknown field(s): {sorted(unknown)}")

    anchor = value.get("anchor")
    if not isinstance(anchor, dict):
        errors.append(f"{ctx}: `{path}.anchor` MUST be an object")
    else:
        anchor_missing = {"kind", "locator"} - set(anchor)
        anchor_unknown = set(anchor) - {"kind", "locator"}
        if anchor_missing:
            errors.append(
                f"{ctx}: `{path}.anchor` missing required field(s): {sorted(anchor_missing)}"
            )
        if anchor_unknown:
            errors.append(f"{ctx}: `{path}.anchor` has unknown field(s): {sorted(anchor_unknown)}")
        if anchor.get("kind") not in _ATTESTATION_ANCHOR_KINDS:
            errors.append(
                f"{ctx}: `{path}.anchor.kind` MUST be one of "
                f"{sorted(_ATTESTATION_ANCHOR_KINDS)}"
            )
        if not isinstance(anchor.get("locator"), str) or not anchor.get("locator"):
            errors.append(f"{ctx}: `{path}.anchor.locator` MUST be a non-empty string")
    if not isinstance(value.get("contentHash"), str) or not value.get("contentHash"):
        errors.append(f"{ctx}: `{path}.contentHash` MUST be a non-empty string")
    if "signer" in value and not isinstance(value["signer"], str):
        errors.append(f"{ctx}: `{path}.signer` is a ClaimReference and MUST be a string")


def check_chain_tx_ref(value, ctx: str, errors: list[str], path: str) -> None:
    """Validate one exact DACS-4 §9.3 ChainTxRef union arm."""
    if not isinstance(value, dict):
        errors.append(f"{ctx}: `{path}` is a ChainTxRef and MUST be an object")
        return
    kind = value.get("kind")
    if kind not in _CHAIN_TX_REF_ARMS:
        errors.append(
            f"{ctx}: `{path}.kind` is not a registered ChainTxRef discriminator: {kind!r}"
        )
        return
    required, optional = _CHAIN_TX_REF_ARMS[kind]
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing:
        errors.append(f"{ctx}: `{path}` ({kind}) missing required field(s): {sorted(missing)}")
    if unknown:
        errors.append(f"{ctx}: `{path}` ({kind}) has unknown field(s): {sorted(unknown)}")

    int_fields = {
        "chainId", "blockNumber", "sourceChainId", "destChainId",
        "recoveryDeadline", "logIndex", "instructionIndex",
    }
    for field in required | optional:
        if field not in value or field == "kind" or field == "receiptAttestation":
            continue
        expected = int if field in int_fields else str
        if not isinstance(value[field], expected) or (
            expected is str and not value[field]
        ):
            errors.append(
                f"{ctx}: `{path}.{field}` MUST be a "
                f"{'number' if expected is int else 'non-empty string'}"
            )
    if kind in {"solana", "solana-instruction"} and value.get("cluster") not in {"mainnet", "devnet", "testnet"}:
        errors.append(f"{ctx}: `{path}.cluster` MUST be mainnet, devnet, or testnet")
    if "receiptAttestation" in value:
        check_attestation_ref(value["receiptAttestation"], ctx, errors, f"{path}.receiptAttestation")


def check_nested_shapes(body: dict, typename: str, types: dict, ctx: str,
                        errors: list[str], path: str = "",
                        seen: frozenset = frozenset()) -> None:
    """Recursively find and validate reference-bearing nested fields.

    Resolves each field's declared type against the type registry; descends into
    nested object types (e.g. AttestationBundle.signatures: BundleSignature[] ->
    BundleSignature.party: ClaimReference). `seen` guards against type cycles.
    `AttestationRef` and `ChainTxRef` receive their exact specialized checks.
    Other named types are traversal paths only: validating every nested type's
    full semantics belongs to the reference verifier and would expand this
    focused shape guard into a second schema implementation.
    """
    spec = types.get(typename)
    if spec is None or typename in seen:
        return
    seen = seen | {typename}
    for fname, ftype in spec["ftypes"].items():
        if fname not in body:
            continue
        here = f"{path}.{fname}" if path else fname
        base, is_arr = _base_and_array(ftype)
        v = body[fname]
        if base == "ClaimReference":
            if is_arr:
                if not (isinstance(v, list) and all(isinstance(x, str) for x in v)):
                    errors.append(f"{ctx}: `{here}` is a ClaimReference[] and MUST be a string array")
            elif not isinstance(v, str):
                errors.append(f'{ctx}: `{here}` is a ClaimReference and MUST be a string '
                              f'("scheme:identifier"), got {type(v).__name__}')
        elif base in {"AttestationRef", "ChainTxRef"}:
            values = v if is_arr and isinstance(v, list) else [v]
            if is_arr and not isinstance(v, list):
                errors.append(f"{ctx}: `{here}` MUST be an array of {base} objects")
                continue
            for idx, value in enumerate(values):
                item_path = f"{here}[{idx}]" if is_arr else here
                if base == "AttestationRef":
                    check_attestation_ref(value, ctx, errors, item_path)
                else:
                    check_chain_tx_ref(value, ctx, errors, item_path)
        elif base in types:  # nested object type — descend
            if is_arr and isinstance(v, list):
                for idx, el in enumerate(v):
                    if isinstance(el, dict):
                        nested_path = f"{here}[{idx}]"
                        check_nested_shapes(el, base, types, ctx, errors, nested_path, seen)
                    else:
                        errors.append(f"{ctx}: `{here}[{idx}]` MUST be a {base} object")
            elif is_arr:
                errors.append(f"{ctx}: `{here}` MUST be an array of {base} objects")
            elif isinstance(v, dict):
                check_nested_shapes(v, base, types, ctx, errors, here, seen)
            else:
                errors.append(f"{ctx}: `{here}` MUST be a {base} object")


# Backward-compatible name used by existing focused tests and external callers.
check_claimrefs = check_nested_shapes


def _artifacts_in(data) -> list[tuple[str, dict]]:
    """Extract (kind, body) pairs from either a lifecycle vector (`artifacts[]`)
    or a single example wrapper (`{kind, artifact}`)."""
    pairs: list[tuple[str, dict]] = []
    arts = data.get("artifacts")
    if isinstance(arts, list):
        for a in arts:
            if isinstance(a, dict) and isinstance(a.get("kind"), str) and isinstance(a.get("artifact"), dict):
                pairs.append((a["kind"], a["artifact"]))
    elif isinstance(data.get("kind"), str) and isinstance(data.get("artifact"), dict):
        pairs.append((data["kind"], data["artifact"]))
    return pairs


def check_file(path: Path, types: dict) -> tuple[list[str], int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    pairs = _artifacts_in(data)
    if not pairs:
        return [], 0
    try:
        rel = str(path.relative_to(ROOT))
    except ValueError:
        rel = path.name
    errors: list[str] = []
    for kind, body in pairs:
        spec = types.get(kind)
        if spec is None:
            errors.append(f"{rel}: kind '{kind}' has no `type {kind}` block in the spec")
            continue
        _check_field_set(body, kind, spec, rel, errors)
        check_nested_shapes(body, kind, types, f"{rel}: {kind}", errors)
    return errors, len(pairs)


def _embedded_reference_artifacts(data) -> list[tuple[str, dict]]:
    """Discover reference-bearing artifacts inside shared fixture wrappers."""
    pairs: list[tuple[str, dict]] = []

    def walk(value) -> None:
        if isinstance(value, dict):
            if value.get("bundleVersion") == "1" and "phaseSummary" in value:
                pairs.append(("AttestationBundle", value))
            elif value.get("bundleVersion") == "1" and "claims" in value:
                pairs.append(("IdentityBundle", value))
            elif value.get("resultVersion") == "1":
                pairs.append(("VerifyResult", value))
            elif value.get("faultBundleVersion") == "1":
                pairs.append(("FaultAttestationBundle", value))
            elif value.get("evidenceVersion") == "1":
                pairs.append(("SettlementEvidence", value))
            elif value.get("replayableDerivationVersion") == "1":
                pairs.append(("ReplayableReputationDerivation", value))
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return pairs


def check_reference_fixture(path: Path, types: dict) -> tuple[list[str], int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    pairs = _embedded_reference_artifacts(data)
    rel = str(path.relative_to(ROOT))
    errors: list[str] = []
    for kind, body in pairs:
        spec = types.get(kind)
        if spec is None:
            errors.append(f"{rel}: kind '{kind}' has no matching spec type")
            continue
        _check_field_set(body, kind, spec, rel, errors)
        check_nested_shapes(body, kind, types, f"{rel}: {kind}", errors)
    return errors, len(pairs)


def check_reference_shape_vector(path: Path) -> tuple[list[str], int]:
    """Execute the positive/negative §7.5.2 and §9.3 shape cases."""
    data = json.loads(path.read_text(encoding="utf-8"))
    errors: list[str] = []
    cases = data.get("vectors")
    if not isinstance(cases, list):
        return [f"{path.relative_to(ROOT)}: vectors MUST be an array"], 0
    for idx, case in enumerate(cases):
        case_errors: list[str] = []
        typename = case.get("type")
        value = case.get("value")
        ctx = f"{path.relative_to(ROOT)}: vector[{idx}] {case.get('name', '<missing-name>')}"
        if typename == "AttestationRef":
            check_attestation_ref(value, ctx, case_errors, "value")
        elif typename == "ChainTxRef":
            check_chain_tx_ref(value, ctx, case_errors, "value")
        else:
            case_errors.append(f"{ctx}: unsupported reference type {typename!r}")
        observed = "fail" if case_errors else "pass"
        if observed != case.get("expected"):
            detail = "; ".join(case_errors) if case_errors else "shape unexpectedly passed"
            errors.append(
                f"{ctx}: expected {case.get('expected')!r}, observed {observed!r}: {detail}"
            )
    return errors, len(cases)


def check_no_legacy_attestation_refs() -> tuple[list[str], int]:
    """Reject the superseded DACS `{kind,id,contentHash}` reference globally.

    The explicit negative cases in REFERENCE_SHAPE_VECTOR are excluded: they
    intentionally preserve the bad bytes to prove rejection.
    """
    errors: list[str] = []
    checked = 0
    for path in sorted((ROOT / "conformance").rglob("*.json")):
        if path == REFERENCE_SHAPE_VECTOR:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue  # the owning structural validator reports malformed JSON

        def walk(value, pointer: str = "") -> None:
            nonlocal checked
            if isinstance(value, dict):
                checked += 1
                if (
                    {"kind", "id", "contentHash"} <= set(value)
                    and isinstance(value.get("kind"), str)
                    and value["kind"].startswith("dacs-")
                ):
                    errors.append(
                        f"{path.relative_to(ROOT)}{pointer}: legacy "
                        "{kind,id,contentHash} reference; use AttestationRef.anchor.locator"
                    )
                for key, child in value.items():
                    walk(child, f"{pointer}/{key}")
            elif isinstance(value, list):
                for idx, child in enumerate(value):
                    walk(child, f"{pointer}/{idx}")

        walk(data)
    return errors, checked


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    types = collect_type_fields()
    if not types:
        print("error: no spec type blocks found — is spec/ present?", file=sys.stderr)
        return 2

    files = sorted(VECTOR_DIR.glob("*.json")) + sorted((VECTOR_DIR / "examples").glob("*.json"))
    errors: list[str] = []
    checked = 0
    skipped: list[str] = []
    for f in files:
        if f.name in QUARANTINE:
            skipped.append(f"{f.name}: {QUARANTINE[f.name]}")
            continue
        errs, n = check_file(f, types)
        errors.extend(errs)
        checked += n

    for f in REFERENCE_FIXTURES:
        errs, n = check_reference_fixture(f, types)
        errors.extend(errs)
        checked += n

    reference_cases = 0
    if REFERENCE_SHAPE_VECTOR.is_file():
        errs, reference_cases = check_reference_shape_vector(REFERENCE_SHAPE_VECTOR)
        errors.extend(errs)
    else:
        errors.append(
            f"{REFERENCE_SHAPE_VECTOR.relative_to(ROOT)}: required #308 shape vector is missing"
        )

    legacy_errors, scanned_objects = check_no_legacy_attestation_refs()
    errors.extend(legacy_errors)

    if not args.quiet:
        print(
            f"validate_artifact_shapes: {len(types)} spec types, checked {checked} artifact(s) "
            f"and {reference_cases} reference-shape case(s); scanned "
            f"{scanned_objects} conformance object(s) for legacy refs"
        )
        for s in skipped:
            print(f"  QUARANTINED (not checked): {s}")
    if errors:
        print(f"FAIL — {len(errors)} artifact shape problem(s):", file=sys.stderr)
        print("\n".join(f"  {e}" for e in errors), file=sys.stderr)
        return 1
    print("OK — all vector/example artifacts match their spec type shape.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
