"""Shared exact-artifact and anchor-history checks for reputation vectors."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import re
from collections.abc import Callable, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from .jcs import canonicalize as jcs_canonicalize
except ImportError:  # Direct execution from scripts/.
    from jcs import canonicalize as jcs_canonicalize


MAX_SAFE_INTEGER = 2**53 - 1
ANCHOR_BINDING_FIELDS = (
    "substrate", "logicalAddress", "nativeAddress", "contentHash", "writer", "nonce",
)
CORE_TRANSITIONS = {
    "submitted": {"accepted", "rejected"},
    "accepted": {"included", "dropped", "replaced", "expired"},
    "included": {"finalized", "reorged"},
    "dropped": {"accepted", "included", "replaced"},
    "expired": {"accepted", "included", "replaced"},
    "reorged": {"accepted", "included", "replaced"},
    "finalized": set(),
    "rejected": set(),
    "replaced": set(),
}
# CORE §5.1 permits a deterministic-BFT binding to declare that valid inclusion
# is final, collapsing one authenticated observation into both `included` and
# `finalized`. DEMOS-MAPPING §A.2 declares inclusion-final semantics under the
# single `demos-bft-final` profile, so that profile authorizes the compressed
# submitted/accepted -> finalized edges without weakening any other non-final,
# late, or replacement check. Any other profile is undeclared and rejected, and
# a history that switches profiles is a cross-profile/mixed-history attempt and
# is likewise rejected.
FINALITY_PROFILE_STANDARD = "demos-bft-final"
COMPRESSED_FINALITY_PREDECESSORS = {"submitted", "accepted"}
SUPPORTED_SIGNATURE_ALGORITHMS = {
    "ed25519", "ecdsa-secp256k1", "sr1-aggregate",
}

# Defensive limits for these synthetic fixture adapters.  They are deliberately
# local to the conformance harness and are not normative DACS maxima.
FIXTURE_MAX_ENCODED_BYTES = 64 * 1024
FIXTURE_MAX_DECODED_BYTES = 48 * 1024
FIXTURE_MAX_NESTING_DEPTH = 64
FIXTURE_MAX_MEMBERS_AND_ELEMENTS = 1024


def jcs_hash(value: object) -> str:
    return hashlib.sha256(jcs_canonicalize(value).encode("utf-8")).hexdigest()


def artifact_hash(value: Mapping[str, object], signature_field: str = "signature") -> str:
    if not isinstance(value, Mapping):
        raise TypeError("signed artifact must be an object")
    unsigned = {key: copy.deepcopy(item) for key, item in value.items() if key != signature_field}
    return jcs_hash(unsigned)


def safe_integer(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_SAFE_INTEGER
    )


def valid_json_number(value: object) -> bool:
    """Return whether value is a CORE B.2 finite, safe-magnitude JSON number."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return abs(value) <= MAX_SAFE_INTEGER
    return (
        isinstance(value, float)
        and math.isfinite(value)
        and abs(value) <= MAX_SAFE_INTEGER
    )


def nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def lowercase_hash(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def valid_transaction_ref(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"kind", "value"}
        and nonempty_string(value.get("kind"))
        and nonempty_string(value.get("value"))
    )


def transaction_key(value: Mapping[str, str]) -> tuple[str, str]:
    return value["kind"], value["value"]


def _decode_base64url(value: object, *, structured: bool = False) -> bytes | None:
    if (
        not isinstance(value, str)
        or not value
        or (structured and len(value) > FIXTURE_MAX_ENCODED_BYTES)
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
        if (
            (structured and len(raw) > FIXTURE_MAX_DECODED_BYTES)
            or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value
        ):
            return None
    except (MemoryError, OverflowError, ValueError, base64.binascii.Error):
        return None
    return raw


def _within_fixture_structure_limits(value: object) -> bool:
    """Bound aggregate JSON structure iteratively before recursive JCS use."""
    pending: list[tuple[object, int]] = [(value, 1)]
    members_and_elements = 0
    while pending:
        current, depth = pending.pop()
        if isinstance(current, dict):
            if depth > FIXTURE_MAX_NESTING_DEPTH:
                return False
            members_and_elements += len(current)
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            if depth > FIXTURE_MAX_NESTING_DEPTH:
                return False
            members_and_elements += len(current)
            pending.extend((item, depth + 1) for item in current)
        if members_and_elements > FIXTURE_MAX_MEMBERS_AND_ELEMENTS:
            return False
    return True


def encode_canonical_object(value: Mapping[str, object]) -> str:
    """Encode one canonical JSON object for a CORE evidence.value fixture."""
    raw = jcs_canonicalize(value).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_canonical_object(value: object) -> dict[str, object] | None:
    """Decode one canonical JSON object, refusing aliases and duplicate members."""
    raw = _decode_base64url(value, structured=True)
    if raw is None:
        return None

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = item
        return result

    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
        if (
            not isinstance(decoded, dict)
            or not _within_fixture_structure_limits(decoded)
            or jcs_canonicalize(decoded).encode("utf-8") != raw
        ):
            return None
    except (
        MemoryError, OverflowError, RecursionError, TypeError, UnicodeDecodeError,
        ValueError,
    ):
        return None
    return decoded


def verify_signed_artifact_status(
    artifact: object,
    domain: str,
    required_unsigned_fields: Iterable[str],
    optional_unsigned_fields: Iterable[str] = (),
    *,
    trusted_signer: str | None = None,
    allow_unknown_unsigned_fields: bool = False,
) -> str:
    """Return pass, fail, or indeterminate for a signed fixture artifact.

    The fixture resolver implements Ed25519 only. The other algorithms registered
    by DACS remain valid protocol choices, so a well-formed envelope using one of
    them is indeterminate here rather than invalid.
    """
    if not isinstance(artifact, dict):
        return "fail"
    required = set(required_unsigned_fields)
    optional = set(optional_unsigned_fields)
    keys = set(artifact)
    if not required <= keys or "signature" not in keys:
        return "fail"
    if not allow_unknown_unsigned_fields and not keys <= required | optional | {"signature"}:
        return "fail"
    if "signature" not in keys:
        return "fail"
    try:
        digest = artifact_hash(artifact)
    except (MemoryError, OverflowError, RecursionError, TypeError, ValueError):
        return "fail"
    return verify_detached_signature_status(
        artifact.get("signature"),
        domain=domain,
        digest=digest,
        signer_field="signer",
        trusted_signer=trusted_signer,
    )


def verify_detached_signature_status(
    signature: object,
    *,
    domain: str,
    digest: str,
    signer_field: str,
    trusted_signer: str | None = None,
) -> str:
    """Verify a closed DACS signature envelope over an already-derived hash."""
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm", signer_field, "value",
    }:
        return "fail"
    algorithm = signature.get("algorithm")
    signer = signature.get(signer_field)
    encoded = signature.get("value")
    if (
        not nonempty_string(signer)
        or _decode_base64url(encoded) is None
        or not lowercase_hash(digest)
        or (trusted_signer is not None and signer != trusted_signer)
    ):
        return "fail"
    if not isinstance(algorithm, str) or algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        return "fail"
    if algorithm != "ed25519":
        return "indeterminate"
    if re.fullmatch(r"key:[0-9a-f]{64}", signer) is None:
        return "indeterminate"
    try:
        raw = _decode_base64url(encoded)
        assert raw is not None
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer[4:]))
        key.verify(raw, (domain + digest).encode("ascii"))
    except (
        AssertionError, InvalidSignature, MemoryError, OverflowError,
        RecursionError, TypeError, ValueError,
    ):
        return "fail"
    return "pass"


def verify_signed_artifact(
    artifact: object,
    domain: str,
    required_unsigned_fields: Iterable[str],
    optional_unsigned_fields: Iterable[str] = (),
    *,
    trusted_signer: str | None = None,
    allow_unknown_unsigned_fields: bool = False,
) -> bool:
    """Compatibility boolean for callers that require a locally verified signature."""
    return verify_signed_artifact_status(
        artifact,
        domain,
        required_unsigned_fields,
        optional_unsigned_fields,
        trusted_signer=trusted_signer,
        allow_unknown_unsigned_fields=allow_unknown_unsigned_fields,
    ) == "pass"


def validate_roster(parties: object) -> bool:
    """Validate the complete canonical roster with globally unique roles and claims."""
    if not isinstance(parties, list) or not parties:
        return False
    rows: list[tuple[str, str, str]] = []
    for party in parties:
        if not isinstance(party, dict) or set(party) != {
            "role", "primaryClaim", "bundleHash",
        }:
            return False
        role = party.get("role")
        claim = party.get("primaryClaim")
        bundle_hash = party.get("bundleHash")
        if (
            not isinstance(role, str)
            or role not in {"buyer", "seller", "orchestrator"}
            or not nonempty_string(claim)
            or not lowercase_hash(bundle_hash)
        ):
            return False
        rows.append((role, claim, bundle_hash))
    roles = [row[0] for row in rows]
    claims = [row[1] for row in rows]
    return (
        {"buyer", "seller"} <= set(roles)
        and len(roles) == len(set(roles))
        and len(claims) == len(set(claims))
        and rows == sorted(rows)
    )


def _valid_block_ref(value: object) -> bool:
    if (
        not isinstance(value, dict)
        or not {"id"} <= set(value) <= {"id", "height", "timestamp"}
        or not nonempty_string(value.get("id"))
    ):
        return False
    if "height" in value and (
        not isinstance(value["height"], str)
        or re.fullmatch(r"0|[1-9][0-9]*", value["height"]) is None
    ):
        return False
    return "timestamp" not in value or safe_integer(value.get("timestamp"))


def _valid_receipt_binding_shape(receipt: Mapping[str, object]) -> bool:
    return (
        nonempty_string(receipt.get("substrate"))
        and nonempty_string(receipt.get("logicalAddress"))
        and nonempty_string(receipt.get("nativeAddress"))
        and lowercase_hash(receipt.get("contentHash"))
        and nonempty_string(receipt.get("writer"))
        and ("nonce" not in receipt or isinstance(receipt.get("nonce"), str))
    )


def _binding_matches(
    receipt: Mapping[str, object],
    expected_binding: Mapping[str, object],
) -> bool:
    """Compare only independently known bindings; adapter evidence covers the rest."""
    if not set(expected_binding) <= set(ANCHOR_BINDING_FIELDS):
        return False
    if "nonce" in expected_binding:
        if "nonce" not in receipt or receipt.get("nonce") != expected_binding.get("nonce"):
            return False
    elif "nonce" in receipt:
        return False
    return all(
        field in receipt and receipt.get(field) == expected
        for field, expected in expected_binding.items()
    )


def _receipt_scope(receipt: Mapping[str, object]) -> dict[str, object]:
    return {
        key: copy.deepcopy(value)
        for key, value in receipt.items()
        if key != "evidence"
    }


def inspect_anchor_receipt(
    receipt: object,
    *,
    expected_binding: Mapping[str, object],
    adapter_domain: str,
    adapter_policy: str,
    trusted_adapter: str,
    authorized_signer: str,
) -> tuple[str, dict[str, object] | None]:
    """Verify a portable CORE receipt and return its trusted fixture metadata."""
    if not isinstance(receipt, dict):
        return "fail", None
    state = receipt.get("state")
    disposition = receipt.get("observationDisposition")
    required = {
        "receiptVersion", "substrate", "logicalAddress", "nativeAddress",
        "contentHash", "writer", "finalityProfile",
        "transactionRef", "state", "observationDisposition", "observedAt",
        "evidence",
    }
    optional = {"nonce", "blockRef", "replacementTransactionRef", "preservedReceiptHash"}
    if isinstance(state, str) and state in {"included", "finalized"}:
        required.add("blockRef")
    if state == "replaced":
        required.add("replacementTransactionRef")
    if disposition == "indeterminate":
        required.add("preservedReceiptHash")
    if (
        not required <= set(receipt) <= required | optional
        or not isinstance(state, str)
        or state not in CORE_TRANSITIONS
        or not isinstance(disposition, str)
        or disposition not in {"established", "indeterminate"}
        or (state != "replaced" and "replacementTransactionRef" in receipt)
        or (disposition != "indeterminate" and "preservedReceiptHash" in receipt)
    ):
        return "fail", None
    if (
        receipt.get("receiptVersion") != "1"
        or not _valid_receipt_binding_shape(receipt)
        or receipt.get("finalityProfile") != "demos-bft-final"
        or not valid_transaction_ref(receipt.get("transactionRef"))
        or not valid_json_number(receipt.get("observedAt"))
        or not _binding_matches(receipt, expected_binding)
    ):
        return "fail", None
    if "blockRef" in receipt and not _valid_block_ref(receipt.get("blockRef")):
        return "fail", None
    if state == "replaced":
        successor = receipt.get("replacementTransactionRef")
        if not valid_transaction_ref(successor):
            return "fail", None
    if disposition == "indeterminate":
        if not lowercase_hash(receipt.get("preservedReceiptHash")):
            return "fail", None
        # Authenticate observation failure too. Only history reconciliation may
        # rely on the referenced established state; this snapshot creates none.
    evidence = receipt.get("evidence")
    if (
        not isinstance(evidence, dict)
        or set(evidence) != {"kind", "value"}
        or evidence.get("kind") != adapter_policy
    ):
        return "fail", None
    adapter_evidence = decode_canonical_object(evidence.get("value"))
    evidence_fields = {
        "anchorEvidenceVersion", "policyId", "receiptHash", "authorizedSigner",
        "nativeOrder", "lineageRootTransactionRef",
    }
    optional_evidence_fields = {"replacementRelation"} if state == "replaced" else set()
    signature_status = verify_signed_artifact_status(
        adapter_evidence,
        adapter_domain,
        evidence_fields,
        optional_evidence_fields,
        trusted_signer=trusted_adapter,
    )
    if signature_status != "pass":
        return signature_status, None
    assert adapter_evidence is not None
    try:
        receipt_scope_hash = jcs_hash(_receipt_scope(receipt))
    except (MemoryError, OverflowError, RecursionError, TypeError, ValueError):
        return "fail", None
    if not (
        adapter_evidence.get("anchorEvidenceVersion") == "1"
        and adapter_evidence.get("policyId") == adapter_policy
        # The trusted adapter attests that this artifact signer authorized the
        # exact writer in receiptHash; writer need not equal the DACS signer.
        and adapter_evidence.get("authorizedSigner") == authorized_signer
        and adapter_evidence.get("receiptHash") == receipt_scope_hash
        and safe_integer(adapter_evidence.get("nativeOrder"))
        and valid_transaction_ref(adapter_evidence.get("lineageRootTransactionRef"))
    ):
        return "fail", None
    if state == "replaced":
        relation = adapter_evidence.get("replacementRelation")
        if not (
            isinstance(relation, dict)
            and set(relation) == {"kind", "predecessor", "replacement"}
            and relation.get("kind") == "authenticated-replacement"
            and relation.get("predecessor") == receipt.get("transactionRef")
            and relation.get("replacement") == receipt.get("replacementTransactionRef")
        ):
            return "fail", None
    return "pass", copy.deepcopy(adapter_evidence)


def verify_anchor_receipt(
    receipt: object,
    *,
    expected_binding: Mapping[str, object],
    adapter_domain: str,
    adapter_policy: str,
    trusted_adapter: str,
    authorized_signer: str,
) -> bool:
    """Compatibility boolean for a locally verified portable AnchorReceipt."""
    status, _ = inspect_anchor_receipt(
        receipt,
        expected_binding=expected_binding,
        adapter_domain=adapter_domain,
        adapter_policy=adapter_policy,
        trusted_adapter=trusted_adapter,
        authorized_signer=authorized_signer,
    )
    # Preserve the standalone boolean contract: an observation failure can only
    # preserve state through the linked-history API, never establish it alone.
    return status == "pass" and receipt.get("observationDisposition") == "established"


def canonical_receipt_history(
    receipts: list[dict],
    native_orders: Mapping[str, int] | None = None,
) -> list[dict]:
    try:
        unique = {jcs_hash(item): item for item in receipts}
    except (MemoryError, OverflowError, RecursionError, TypeError, ValueError):
        return []
    if native_orders is None:
        native_orders = {}
        for digest, receipt in unique.items():
            evidence = receipt.get("evidence") if isinstance(receipt, dict) else None
            adapter_result = (
                decode_canonical_object(evidence.get("value"))
                if isinstance(evidence, dict)
                else None
            )
            native_order = adapter_result.get("nativeOrder") if adapter_result else None
            native_orders[digest] = native_order if safe_integer(native_order) else MAX_SAFE_INTEGER
    return [
        copy.deepcopy(item)
        for digest, item in sorted(
            unique.items(), key=lambda pair: (native_orders[pair[0]], pair[0])
        )
    ]


def _replacement_graph_has_cycle(
    edges: Mapping[tuple[str, str], tuple[tuple[str, str], int]],
) -> bool:
    # Each predecessor has at most one successor, so a three-colour walk can be
    # iterative and O(V) without recursion depth depending on fixture length.
    state: dict[tuple[str, str], int] = {}
    for start in edges:
        if state.get(start) == 2:
            continue
        trail: list[tuple[str, str]] = []
        node = start
        while node in edges and state.get(node, 0) == 0:
            state[node] = 1
            trail.append(node)
            node = edges[node][0]
        if state.get(node) == 1:
            return True
        for visited in trail:
            state[visited] = 2
    return False


def resolve_anchor_history(
    selected: object,
    receipts: object,
    *,
    expected_binding: Mapping[str, object],
    receipt_verifier: Callable[[object], tuple[str, dict[str, object] | None]],
    expected_lineage_root: Mapping[str, str] | None = None,
    allow_implicit_selection: bool = False,
) -> tuple[str, dict | None, list[dict]]:
    """Reconcile a complete trusted lineage ending at the exact selected receipt."""
    implicit_selection = selected is None and allow_implicit_selection
    if (
        (not implicit_selection and not isinstance(selected, dict))
        or not isinstance(receipts, list)
        or not receipts
    ):
        return "indeterminate", None, []
    metadata: dict[str, dict[str, object]] = {}
    for item in receipts:
        status, verified_metadata = receipt_verifier(item)
        if status != "pass" or verified_metadata is None:
            return "indeterminate", None, []
        try:
            metadata[jcs_hash(item)] = verified_metadata
        except (MemoryError, OverflowError, RecursionError, TypeError, ValueError):
            return "indeterminate", None, []
    native_orders = {
        digest: item["nativeOrder"]
        for digest, item in metadata.items()
    }
    history = canonical_receipt_history(receipts, native_orders)
    if not implicit_selection and selected not in history:
        return "indeterminate", None, history

    positions: dict[tuple[tuple[str, str], int], set[str]] = {}
    by_transaction: dict[tuple[str, str], list[dict]] = {}
    for item in history:
        digest = jcs_hash(item)
        key = transaction_key(item["transactionRef"])
        native_order = metadata[digest]["nativeOrder"]
        positions.setdefault((key, native_order), set()).add(digest)
        by_transaction.setdefault(key, []).append(item)
    if any(len(digests) > 1 for digests in positions.values()):
        return "indeterminate", None, history

    established_by_transaction: dict[tuple[str, str], list[dict]] = {}
    last_established: dict[tuple[str, str], dict] = {}
    for key, snapshots in by_transaction.items():
        last = None
        previous_order = -1
        established = []
        for item in snapshots:
            native_order = metadata[jcs_hash(item)]["nativeOrder"]
            if native_order <= previous_order:
                return "indeterminate", None, history
            previous_order = native_order
            if item["observationDisposition"] == "indeterminate":
                if (
                    last is None
                    or item.get("preservedReceiptHash") != jcs_hash(last)
                    or item["state"] != last["state"]
                    or any(item.get(field) != last.get(field)
                           for field in ANCHOR_BINDING_FIELDS)
                    or item["transactionRef"] != last["transactionRef"]
                    or item["finalityProfile"] != last["finalityProfile"]
                ):
                    return "indeterminate", None, history
                # Retain the exact established receipt as authority, including
                # its block/finality facts; do not treat failure as a transition.
                continue
            if last is not None and item["state"] not in CORE_TRANSITIONS[last["state"]]:
                compressed_finality = (
                    item["state"] == "finalized"
                    and last["state"] in COMPRESSED_FINALITY_PREDECESSORS
                    and item.get("finalityProfile") == FINALITY_PROFILE_STANDARD
                )
                if not compressed_finality:
                    return "indeterminate", None, history
            last = item
            established.append(item)
        if last is not None:
            established_by_transaction[key] = established
            last_established[key] = last

    edges_by_predecessor: dict[tuple[str, str], list[tuple[tuple[str, str], int]]] = {}
    for key, snapshots in established_by_transaction.items():
        states = {item["state"] for item in snapshots}
        if "finalized" in states and "replaced" in states:
            return "indeterminate", None, history
        for item in snapshots:
            if item["state"] == "replaced":
                item_metadata = metadata[jcs_hash(item)]
                successor = transaction_key(item["replacementTransactionRef"])
                edges_by_predecessor.setdefault(key, []).append(
                    (successor, item_metadata["nativeOrder"])
                )
    if any(len({successor for successor, _ in values}) > 1 for values in edges_by_predecessor.values()):
        return "indeterminate", None, history
    edges = {key: values[0] for key, values in edges_by_predecessor.items()}
    if _replacement_graph_has_cycle(edges):
        return "indeterminate", None, history
    for successor, edge_order in edges.values():
        if any(
            metadata[jcs_hash(item)]["nativeOrder"] <= edge_order
            for item in established_by_transaction.get(successor, [])
            if item["state"] in {"finalized", "replaced"}
        ):
            return "indeterminate", None, history

    lineage_roots = {
        transaction_key(item["lineageRootTransactionRef"])
        for item in metadata.values()
    }
    if len(lineage_roots) != 1:
        return "indeterminate", None, history
    root = next(iter(lineage_roots))
    if expected_lineage_root is not None and (
        not valid_transaction_ref(expected_lineage_root)
        or root != transaction_key(expected_lineage_root)
    ):
        return "indeterminate", None, history
    if root not in by_transaction or root in {successor for successor, _ in edges.values()}:
        return "indeterminate", None, history
    if implicit_selection:
        terminal_keys = [key for key in by_transaction if key not in edges]
        if len(terminal_keys) != 1:
            return "indeterminate", None, history
        selected_key = terminal_keys[0]
    else:
        selected_key = transaction_key(selected["transactionRef"])
    lineage: set[tuple[str, str]] = set()
    cursor = root
    while True:
        if cursor in lineage:
            return "indeterminate", None, history
        lineage.add(cursor)
        if cursor == selected_key:
            break
        if cursor not in edges:
            return "indeterminate", None, history
        cursor = edges[cursor][0]
    if set(by_transaction) != lineage:
        return "indeterminate", None, history
    finalized = [
        item for key, item in last_established.items()
        if key in lineage and item["state"] == "finalized"
    ]
    if len(finalized) != 1 or (
        not implicit_selection and selected != finalized[0]
    ):
        return "indeterminate", None, history
    if not _binding_matches(finalized[0], expected_binding):
        return "fail", None, history
    return "pass", copy.deepcopy(finalized[0]), history
