#!/usr/bin/env python3
"""Deterministic full-chain generator for the DACS v0.1 lifecycle vectors.

Regenerates the five-artifact chains in
  conformance/vectors/dacs-v0.1-happy-path.json
  conformance/vectors/dacs-v0.1-negative-paths.json
so every cross-reference resolves to the referent's §B.2 signature-omitted content
hash and every artifact carries a valid Ed25519 signature over its §B.2 scope, except
the one deliberately tampered signature the negative chain declares.

All hashing and canonicalisation is IMPORTED from scripts/validate_conformance_vectors.py
— this module adds none of its own:
  - artifact_hash_hex / content_hash_uri  (§B.2 signature-omitted hash; RFC 8785 JCS)
  - canonical_json                         (the single JCS serializer; also used for
                                            bare sub-object digests, e.g. terms.deliverable.hash)
  - HASH_EXCLUDED / signing_scope          (per-kind hash-excluded fields)
  - KIND_SEPARATOR                         (registry-validated §B.7 domain separators)
  - signature_entries / observed_signature_checks

Keys are DERIVED from 32-byte repeated seeds 0x41/0x42/0x43; public keys are never
hard-coded. The signature-value spelling is a parameter (`encode_signature`): the
committed fixtures carry canonical SIG-6 (unpadded Base64URL); `'legacy'` (padded
standard Base64) exists only for byte-comparable reproduction of prior spellings.

Both CLI modes render through ONE shared path (render_document); a fail closes the
gate with a distinct, condition-naming message. An explicit mode is required — a
bare invocation prints usage and exits non-zero.

CLI:
  --write  staging-first regeneration of both fixtures in place (canonical SIG-6):
           render AND validate both chains, then write both. The guarantee is
           gate-conditional: if ANY gate condition fails, no fixture is written.
           It is NOT transactional against I/O: the two writes are sequential and
           unprotected, so a permissions error or disk-full on the second leaves
           the first already replaced.
  --check  read-only fail-closed gate. Renders both chains through the write path and
           enforces six conditions — byte drift, unexpected signature distribution,
           opaque-input change, unresolved reference, nondeterminism, and cannot-run —
           writing nothing, ever. The MATCH/DIFFER reproduction table is printed for
           information only and can never set the exit code.

Scope of --check. It discriminates on the corpus's regenerable content: derived
cross-references, signed §B.2 scopes, signature spellings, the tamper distribution,
generator determinism, and any divergence between the generator and the committed
bytes from either side. It proves the corpus is a FIXED POINT of the generator —
re-rendering the committed document reproduces it byte-for-byte. It does NOT prove
the generator PRODUCES the corpus from an independent source. Because it renders
from `before = json.loads(committed)` and echoes every field it does not derive, a
corruption in a field that is both echoed verbatim AND excluded from the signed hash
appears identically on both sides of the byte comparison and cancels — so --check
cannot see it (confirmed instances: the wrapper-level `id`, and `anchoredByRole`,
hash-excluded per DACS-5 §10.4.1). This is a structural consequence of
render-and-compare-to-self; closing the class needs a generator that builds the
document from an independent declarative source rather than from the committed file.
Until then the residual class is guarded by the committed-fixture hash baseline in
tests/test_generate_lifecycle_vectors_check.py, which trips on any byte change.
"""
import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_conformance_vectors as vcv  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
HAPPY = ROOT / "conformance" / "vectors" / "dacs-v0.1-happy-path.json"
NEGATIVE = ROOT / "conformance" / "vectors" / "dacs-v0.1-negative-paths.json"

# Repeated-byte Ed25519 seeds. Keys derived in code; pubkeys never hard-coded.
SEED_BYTES = (0x41, 0x42, 0x43)


def derived_keys():
    """{ derived-public-hex : Ed25519PrivateKey } for the three synthetic seeds."""
    keys = {}
    for b in SEED_BYTES:
        priv = Ed25519PrivateKey.from_private_bytes(bytes([b]) * 32)
        pub_hex = priv.public_key().public_bytes_raw().hex()
        keys[pub_hex] = priv
    return keys


def signer_pub_hex(signer):
    """Extract the 64-hex public key from a 'cci:<hex>' signer/party claim."""
    return str(signer).split(":", 1)[1] if ":" in str(signer) else str(signer)


def hash_hex_subobject(value):
    """sha256 hex over the §B.2 canonical form (RFC 8785 JCS) of a sub-object.

    Used for terms.deliverable.hash (a bare object digest, not an artifact envelope,
    so it carries no §B.2 field exclusion). This delegates to the same canonical_json
    primitive the validator uses for artifact hashing and signing, so every hash in the
    corpus derives from ONE canonicalizer — never json.dumps, which only coincides with
    JCS on ASCII/float-free input."""
    return hashlib.sha256(vcv.canonical_json(value)).hexdigest()


# Opaque input digests that regeneration MUST leave byte-identical: they are inputs
# (vet-evidence / on-chain tx digests), not artifact-envelope edges. Collected by
# key name anywhere in the chain and asserted unchanged post-regeneration.
OPAQUE_DIGEST_KEYS = (
    "bundleHash", "requirementHash", "lockTxHash", "revealTxHash",
)


def _collect_opaque(data):
    """[(json-path, value)] for every opaque input digest, in document order.
    Covers OPAQUE_DIGEST_KEYS plus dealSpecific[*].contentHash (a nested contentHash
    that is a payload digest, not an envelope reference)."""
    found = []

    def walk(node, path, in_deal_specific):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in OPAQUE_DIGEST_KEYS and isinstance(v, str):
                    found.append((path + "/" + k, v))
                if k == "contentHash" and in_deal_specific and isinstance(v, str):
                    found.append((path + "/" + k, v))
                walk(v, path + "/" + k, in_deal_specific or (k == "dealSpecific"))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]", in_deal_specific)

    for item in data["artifacts"]:
        walk(item, item["id"], False)
    return found


_HEX64 = re.compile(r"(?:sha256:)?[0-9a-f]{64}")


def assert_unique_kinds(data):
    """Fail loudly if two artifacts share a kind — `by_kind = {a["kind"]: ...}` would
    otherwise silently drop one, and the chain would be regenerated against the survivor."""
    kinds = [a["kind"] for a in data["artifacts"]]
    if len(kinds) != len(set(kinds)):
        dupes = sorted({k for k in kinds if kinds.count(k) > 1})
        raise ValueError(f"duplicate artifact kind(s), by_kind would drop one: {dupes}")


def assert_domain_separators(data):
    """Verify each artifact's stored `domainSeparator` equals KIND_SEPARATOR[kind] BEFORE
    signing. The generator signs under KIND_SEPARATOR; the tests verify under the stored
    field. A mismatch must surface here, not be silently healed by a write-back."""
    for item in data["artifacts"]:
        kind = item["kind"]
        stored = item.get("domainSeparator")
        expected = vcv.KIND_SEPARATOR[kind]
        if stored != expected:
            raise ValueError(
                f"{item['id']}: stored domainSeparator {stored!r} != "
                f"KIND_SEPARATOR[{kind!r}] {expected!r}")


class UnresolvedReferenceError(ValueError):
    """A 64-hex value in the regenerated chain resolves to no known artifact §B.2
    hash, sub-object digest, or declared opaque input. A ValueError SUBCLASS so
    every existing `except ValueError` still catches it, but a distinct TYPE so
    the --check gate classifies condition 4 (UNRESOLVED-REFERENCE) structurally by
    type, never by matching the words in the message."""


def assert_all_references_resolve(data):
    """Post-regeneration guard: every 64-hex (or 'sha256:'+64-hex) string in the chain must
    resolve to a known artifact §B.2 hash, a known sub-object digest (terms.deliverable.hash),
    or a declared opaque input. Anything else — a cross-reference this generator does not
    rewrite, or one left stale — aborts loudly instead of shipping silently."""
    artifact_b2 = set()
    subobject = set()
    for item in data["artifacts"]:
        art = item["artifact"]
        artifact_b2.add(vcv.artifact_hash_hex(item["kind"], art))
        deliverable = art.get("offering", {}).get("deliverable")
        if isinstance(deliverable, dict):
            subobject.add(hash_hex_subobject(deliverable))
    opaque = {v for _, v in _collect_opaque(data) if re.fullmatch(r"[0-9a-f]{64}", v)}
    known = artifact_b2 | subobject | opaque

    unresolved = []

    def walk(node, path):
        if isinstance(node, str):
            if _HEX64.fullmatch(node):
                bare = node[len("sha256:"):] if node.startswith("sha256:") else node
                if bare not in known:
                    unresolved.append((path, node))
        elif isinstance(node, dict):
            for k, v in node.items():
                walk(v, path + "/" + k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    for item in data["artifacts"]:
        walk(item, item["id"])
    if unresolved:
        raise UnresolvedReferenceError(
            "unresolved 64-hex value(s) after regeneration — a cross-reference may be "
            f"unhandled or left stale: {unresolved}")


def signing_payload(kind, artifact):
    """Exactly what the repo verifies: separator || §B.2 artifact_hash_hex, ASCII."""
    return (vcv.KIND_SEPARATOR[kind] + vcv.artifact_hash_hex(kind, artifact)).encode("ascii")


def encode_signature(raw, spelling):
    if spelling == "legacy":
        return base64.b64encode(raw).decode("ascii")          # padded standard Base64
    if spelling == "sig6":
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")  # SIG-6
    raise ValueError(f"unknown spelling {spelling!r}")


def resign_value(kind, artifact, priv, spelling):
    """Sign the artifact's current §B.2 scope with priv; return the encoded value."""
    raw = priv.sign(signing_payload(kind, artifact))
    return encode_signature(raw, spelling)


# ---------------------------------------------------------------------------
# Reproduction proof (Step-2 gate): recompute each stored signature in place.
# ---------------------------------------------------------------------------
def reproduce(path, keys):
    """Return rows [(file, artifactId, sigPath, signerShort, raw_match, str_match, stored, recomputed)]."""
    data = json.loads(path.read_text(encoding="utf-8"))
    fname = path.name
    rows = []
    for item in data["artifacts"]:
        kind = item["kind"]
        artifact = item["artifact"]
        for sig_path, envelope in vcv.signature_entries(artifact):
            envelope = envelope if isinstance(envelope, dict) else {}
            signer = envelope.get("signer") or envelope.get("party")
            stored = envelope.get("value")
            pub_hex = signer_pub_hex(signer)
            priv = keys.get(pub_hex)
            if priv is None:
                rows.append((fname, item["id"], sig_path, pub_hex[:8], "NO-KEY", "NO-KEY", stored, None))
                continue
            # Spelling-agnostic RAW comparison: decode the stored value in its OWN
            # spelling (SIG-6 tried first, then legacy) and compare to the freshly-signed
            # raw bytes. This compares like-for-like across the legacy->SIG-6 migration —
            # raw signature bytes are spelling-independent.
            raw_fresh = priv.sign(signing_payload(kind, artifact))
            try:
                raw_stored = vcv.decode_signature_value(stored, legacy_allowed=True)
            except Exception:
                raw_stored = None
            raw_match = (raw_stored == raw_fresh)
            # String comparison, like-for-like: re-encode the fresh signature in the
            # stored value's detected spelling.
            spelling = "sig6" if vcv._is_canonical_sig6(stored) else "legacy"
            recomputed = encode_signature(raw_fresh, spelling)
            str_match = (stored == recomputed)
            rows.append((fname, item["id"], sig_path, pub_hex[:8],
                         raw_match, str_match, stored, recomputed))
    return rows


# ---------------------------------------------------------------------------
# Full-chain regeneration (used here only for the in-memory determinism proof;
# fixture writing is Step 3). Positive-chain coherent regeneration.
# ---------------------------------------------------------------------------
def regenerate_positive(data, spelling="legacy"):
    """Return a NEW data dict: cross-refs → §B.2 hashes, artifacts re-signed,
    envelope contentHash + signatureChecks recomputed. Pure; does not mutate input."""
    data = json.loads(json.dumps(data))  # deep copy, stable ordering
    assert_unique_kinds(data)
    by_kind = {a["kind"]: a for a in data["artifacts"]}
    listing = by_kind["Listing"]["artifact"]
    composite = by_kind["CompositeVerificationRecord"]["artifact"]

    # Topological order: Listing + Composite are leaves (no outbound artifact ref).
    listing_b2 = vcv.artifact_hash_hex("Listing", listing)
    composite_b2 = vcv.artifact_hash_hex("CompositeVerificationRecord", composite)

    agreement = by_kind["AgreementDocument"]["artifact"]
    agreement["listingRef"]["contentHash"] = listing_b2
    for party in agreement.get("parties", []):
        if "vetRecordRef" in party:
            party["vetRecordRef"]["contentHash"] = composite_b2
    agreement["terms"]["deliverable"]["hash"] = hash_hex_subobject(
        listing["offering"]["deliverable"])

    bundle = by_kind["AttestationBundle"]["artifact"]
    bundle["listingRef"]["contentHash"] = listing_b2

    # Signing separator (KIND_SEPARATOR) must match each artifact's stored domainSeparator,
    # which the tests verify under — assert before signing, never write back.
    assert_domain_separators(data)

    # Re-sign every artifact over its (now-updated) §B.2 scope, then set envelope hash and
    # recompute signatureChecks from observed verification (same source of truth as
    # validate_conformance_vectors.write_vectors).
    keys = derived_keys()
    registry = vcv.load_registered_domain_separators(vcv.ROOT)
    legacy_allowed = (spelling == "legacy")  # SIG-6 decodes without the permit
    for item in data["artifacts"]:
        kind = item["kind"]
        artifact = item["artifact"]
        for sig_path, envelope in vcv.signature_entries(artifact):
            if not isinstance(envelope, dict):
                continue
            signer = envelope.get("signer") or envelope.get("party")
            priv = keys.get(signer_pub_hex(signer))
            if priv is not None:
                envelope["value"] = resign_value(kind, artifact, priv, spelling)
        item["contentHash"] = vcv.content_hash_uri(kind, artifact)
        item["signatureChecks"] = vcv.observed_signature_checks(
            kind, artifact, registry, legacy_allowed)
    assert_all_references_resolve(data)
    return data


# The negative chain's DACS-5 defect: signatures[<idx>] of this artifact is byte-flipped
# so it does NOT verify. Declared once, structurally — the tamper lands here and NOWHERE
# else. (The DACS-4 defect is semantic — outcome/reason on neg-settlement-tampered-preimage
# — and needs no signature manipulation: that artifact is re-signed like any other and its
# signature still verifies.)
DACS5_SIGNATURE_TAMPER = ("neg-bundle-tampered-signature", 0)


def _decode_value(value, spelling):
    """Decode a signature value in the given spelling to raw bytes."""
    if spelling == "sig6":
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    return base64.b64decode(value, validate=True)  # legacy padded standard Base64


def tamper_signature_value(value, spelling="legacy"):
    """Deterministically invalidate an ed25519 signature by flipping the low bit of its
    first RAW byte, then re-encoding in the same spelling. Same input always yields the
    same output — no randomness, no timestamp. Length-preserving (still 64 bytes), so it
    decodes cleanly and then fails ed25519 verification, i.e. observed as expect:'fail'.

    Operating on raw bytes makes the tamper spelling-invariant: the tampered RAW bytes are
    identical whether emitted as legacy padded Base64 or canonical SIG-6 — a respelling
    re-encodes the same tampered bytes, it does not re-tamper."""
    raw = bytearray(_decode_value(value, spelling))
    raw[0] ^= 0x01
    return encode_signature(bytes(raw), spelling)


def regenerate_negative(data, spelling="legacy"):
    """Coherent negative-chain regeneration, then the DACS-5 tamper re-applied LAST.

    5a ordering: the DPA-1 verificationMethod is added to the Listing deliverable BEFORE
    any dependent hash is computed, because it changes both the Listing §B.2 hash and
    hash_hex(offering.deliverable). Pure; does not mutate input."""
    data = json.loads(json.dumps(data))  # deep copy, stable ordering
    assert_unique_kinds(data)
    by_kind = {a["kind"]: a for a in data["artifacts"]}
    listing = by_kind["Listing"]["artifact"]

    # 1. Add the DPA-1 verificationMethod the happy-path Listing already carries.
    listing["offering"]["deliverable"]["verificationMethod"] = {"kind": "self-signed"}

    # 2. Compute dependent §B.2 hashes from the UPDATED objects (Listing/Composite leaves).
    composite = by_kind["CompositeVerificationRecord"]["artifact"]
    listing_b2 = vcv.artifact_hash_hex("Listing", listing)
    composite_b2 = vcv.artifact_hash_hex("CompositeVerificationRecord", composite)

    agreement = by_kind["AgreementDocument"]["artifact"]
    agreement["listingRef"]["contentHash"] = listing_b2
    for party in agreement.get("parties", []):
        if "vetRecordRef" in party:
            party["vetRecordRef"]["contentHash"] = composite_b2
    agreement["terms"]["deliverable"]["hash"] = hash_hex_subobject(
        listing["offering"]["deliverable"])

    bundle = by_kind["AttestationBundle"]["artifact"]
    bundle["listingRef"]["contentHash"] = listing_b2

    # Signing separator (KIND_SEPARATOR) must match each artifact's stored domainSeparator.
    assert_domain_separators(data)

    # 3. Re-sign every artifact over its updated §B.2 scope (all valid at this point,
    #    including neg-settlement-tampered-preimage — its DACS-4 defect is semantic).
    keys = derived_keys()
    for item in data["artifacts"]:
        kind = item["kind"]
        artifact = item["artifact"]
        for sig_path, envelope in vcv.signature_entries(artifact):
            if not isinstance(envelope, dict):
                continue
            signer = envelope.get("signer") or envelope.get("party")
            priv = keys.get(signer_pub_hex(signer))
            if priv is not None:
                envelope["value"] = resign_value(kind, artifact, priv, spelling)

    # 4. Re-apply the DACS-5 tamper LAST — to a freshly-valid signature. Routed through the
    #    same signature_entries model every other walk uses (one model of where signatures
    #    live), and asserted to land on EXACTLY one site.
    tamper_id, tamper_idx = DACS5_SIGNATURE_TAMPER
    tamper_path = f"signatures[{tamper_idx}]"
    applied = 0
    for item in data["artifacts"]:
        if item["id"] != tamper_id:
            continue
        for sig_path, envelope in vcv.signature_entries(item["artifact"]):
            if sig_path == tamper_path and isinstance(envelope, dict):
                envelope["value"] = tamper_signature_value(envelope["value"], spelling)
                applied += 1
    if applied != 1:
        raise ValueError(
            f"DACS-5 tamper must land on exactly one site "
            f"({tamper_id} {tamper_path}); applied to {applied}")

    # 5. Envelope contentHash (signature-omitted) + signatureChecks recomputed AFTER the
    #    tamper, so the tampered signature is observed as expect:'fail' and every other
    #    signature as expect:'verify'.
    registry = vcv.load_registered_domain_separators(vcv.ROOT)
    legacy_allowed = (spelling == "legacy")  # SIG-6 decodes without the permit
    for item in data["artifacts"]:
        kind = item["kind"]
        artifact = item["artifact"]
        item["contentHash"] = vcv.content_hash_uri(kind, artifact)
        item["signatureChecks"] = vcv.observed_signature_checks(
            kind, artifact, registry, legacy_allowed)
    assert_all_references_resolve(data)
    return data


# ---------------------------------------------------------------------------
# ONE render path, shared by --write and --check (a mirrored second copy is the
# defect being corrected). The two lifecycle chains, in write/read order.
# ---------------------------------------------------------------------------
CHAINS = ((HAPPY, regenerate_positive), (NEGATIVE, regenerate_negative))


def render_document(before, regen):
    """THE single render function. Given a committed document and its chain
    regenerator, return (after_doc, rendered_text) where rendered_text is the
    EXACT bytes --write writes: regenerate over §B.2 as canonical SIG-6, drop the
    top-level signatureValueSpelling declaration (SIG-6 files carry none), then
    json.dumps(indent=2, ensure_ascii=False) + trailing newline. Both modes call
    this and only this; neither owns a second copy of the render."""
    after = regen(before, spelling="sig6")
    after.pop("signatureValueSpelling", None)
    return after, json.dumps(after, indent=2, ensure_ascii=False) + "\n"


class _GateFail(Exception):
    """One failed gate condition. The message IS the full stderr line, prefixed
    with a distinct [CONDITION] tag naming the condition and the chain."""


def _load_committed(path):
    """Return (text, dict). Condition 6 (cannot run) for a missing/unreadable/
    malformed fixture — a LOUD message explicitly NOT a drift failure."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise _GateFail(
            f"[CANNOT-RUN] {path.name}: committed fixture is missing ({path}). "
            "Gate could not run — this is NOT a drift/PASS result.")
    except OSError as e:
        raise _GateFail(
            f"[CANNOT-RUN] {path.name}: committed fixture is unreadable ({e}). "
            "Gate could not run — this is NOT a drift/PASS result.")
    try:
        return text, json.loads(text)
    except json.JSONDecodeError as e:
        raise _GateFail(
            f"[CANNOT-RUN] {path.name}: committed fixture is not valid JSON ({e}). "
            "Gate could not run — this is NOT a drift/PASS result.")


def _render_twice(path, before, regen):
    """Render the chain TWICE through render_document; return (after1, text1, text2).
    Classifies render-time failures: an unresolved reference (condition 4) gets its
    own message; any other regeneration abort or crypto failure is condition 6."""
    try:
        after1, text1 = render_document(before, regen)
        _after2, text2 = render_document(before, regen)
    except _GateFail:
        raise
    except UnresolvedReferenceError as e:  # classify by TYPE, before the ValueError arm
        raise _GateFail(
            f"[UNRESOLVED-REFERENCE] {path.name}: a 64-hex reference in the rendered "
            f"chain resolves to no known artifact/sub-object/opaque digest: {e}")
    except ValueError as e:
        raise _GateFail(
            f"[CANNOT-RUN] {path.name}: regeneration aborted on a structural invariant "
            f"before producing bytes ({e}). NOT a drift failure.")
    except Exception as e:  # e.g. cryptography missing/broken at sign time
        raise _GateFail(
            f"[CANNOT-RUN] {path.name}: regeneration raised {type(e).__name__}: {e}. "
            "Gate could not run — NOT a drift failure.")
    return after1, text1, text2


def _check_references(path, after):
    """Condition 4 — assert_all_references_resolve on the RENDERED chain (both
    chains, explicitly, per this step's design).

    Backstop, not the primary path: render_document already runs the regenerator,
    which calls assert_all_references_resolve and raises UnresolvedReferenceError
    first, so _render_twice normally classifies this condition. This explicit call
    only fires if the regenerator ever stopped raising."""
    try:
        assert_all_references_resolve(after)
    except UnresolvedReferenceError as e:
        raise _GateFail(
            f"[UNRESOLVED-REFERENCE] {path.name}: {e}")


def _check_opaque(path, before, after):
    """Condition 3 — opaque input digests (path-set AND every digest) must be
    byte-identical before vs after regeneration."""
    b_map = dict(_collect_opaque(before))
    a_map = dict(_collect_opaque(after))
    if set(b_map) != set(a_map):
        raise _GateFail(
            f"[OPAQUE-INPUT] {path.name}: the set of opaque-input digest paths changed "
            f"during regeneration (added={sorted(set(a_map) - set(b_map))}, "
            f"removed={sorted(set(b_map) - set(a_map))}).")
    changed = [(p, b_map[p], a_map[p]) for p in b_map if b_map[p] != a_map[p]]
    if changed:
        raise _GateFail(
            f"[OPAQUE-INPUT] {path.name}: an opaque input digest changed during "
            f"regeneration (must be byte-identical): {changed}.")


def _check_determinism(path, text1, text2):
    """Condition 5 — two consecutive renders of the chain must be byte-identical
    (the RENDERED complete-document bytes, not a sort_keys re-serialisation)."""
    if text1 != text2:
        raise _GateFail(
            f"[NONDETERMINISM] {path.name}: two consecutive renders produced different "
            "bytes; the generator is not deterministic.")


def _check_drift(path, text1, committed_text):
    """Condition 1 (--check only) — the rendered complete document must equal the
    committed fixture byte-for-byte."""
    if text1 != committed_text:
        raise _GateFail(
            f"[DRIFT] {path.name}: rendered bytes differ from the committed fixture — "
            "the generator and the committed vector have diverged "
            f"(rendered {len(text1)} bytes vs committed {len(committed_text)} bytes).")


def _check_distribution(after_docs):
    """Condition 2 — corpus-wide signature distribution, derived (never a literal)
    from validate_conformance_vectors.INTENTIONAL_SIGNATURE_TAMPERS: every stored
    signature must verify except exactly that declared tamper set."""
    total = 0
    observed_fail_pins = set()
    for after in after_docs:
        for art in after["artifacts"]:
            for pin in art.get("signatureChecks", []):
                total += 1
                if pin.get("expect") != "verify":
                    observed_fail_pins.add((pin["path"], art["id"]))
    expected = set(vcv.INTENTIONAL_SIGNATURE_TAMPERS)
    verify_count = total - len(observed_fail_pins)
    expected_verify = total - len(expected)
    if observed_fail_pins != expected or verify_count != expected_verify:
        raise _GateFail(
            "[SIGNATURE-DISTRIBUTION] corpus: unexpected signature distribution "
            f"(total={total}, verify={verify_count}, "
            f"observed_fail_pins={sorted(observed_fail_pins)}); expected "
            f"{expected_verify} verify + failures exactly {sorted(expected)} "
            "(derived from validate_conformance_vectors.INTENTIONAL_SIGNATURE_TAMPERS).")


def _run_gate(mode):
    """Render + validate BOTH chains. Returns (failures, rendered) where failures
    is a list of distinct stderr lines (empty == green) and rendered maps path ->
    rendered bytes. Writes NOTHING. mode is 'check' (drift enforced) or 'write'
    (drift skipped — the write intentionally changes bytes)."""
    failures = []
    rendered = {}
    after_docs = []
    for path, regen in CHAINS:
        try:
            committed_text, before = _load_committed(path)
            after1, text1, text2 = _render_twice(path, before, regen)
            _check_references(path, after1)      # condition 4
            _check_opaque(path, before, after1)  # condition 3
            _check_determinism(path, text1, text2)  # condition 5
            if mode == "check":
                _check_drift(path, text1, committed_text)  # condition 1
            rendered[path] = text1
            after_docs.append(after1)
        except _GateFail as e:
            failures.append(str(e))
    # Condition 2 is corpus-wide; only assessable if BOTH chains rendered.
    if len(after_docs) == len(CHAINS):
        try:
            _check_distribution(after_docs)
        except _GateFail as e:
            failures.append(str(e))
    else:
        failures.append(
            "[SIGNATURE-DISTRIBUTION] corpus: NOT evaluated — a chain failed to render "
            "(see above); the corpus-wide distribution cannot be assessed. NOT a PASS.")
    return failures, rendered


def _print_reproduction_table():
    """Informational only (B6): the MATCH/DIFFER raw-signature reproduction table.
    A printed row here can NEVER set the exit code — the verdict comes solely from
    the six gate conditions in _run_gate."""
    keys = derived_keys()
    print("Derived public keys from seeds 0x41/0x42/0x43:")
    for b in SEED_BYTES:
        priv = Ed25519PrivateKey.from_private_bytes(bytes([b]) * 32)
        print(f"  0x{b:02x} -> {priv.public_key().public_bytes_raw().hex()}")
    print()

    all_rows = []
    for path in (HAPPY, NEGATIVE):
        all_rows.extend(reproduce(path, keys))

    print(f"{'file':30} {'artifactId':34} {'sigPath':14} {'signer':9} {'raw':6} {'str':6}")
    match_raw = differ = 0
    disagreements = []
    for (f, aid, sp, sg, rawm, strm, stored, recomp) in all_rows:
        verdict = "MATCH" if rawm is True else ("DIFFER" if rawm is False else str(rawm))
        print(f"{f:30} {aid:34} {sp:14} {sg:9} {str(rawm):6} {str(strm):6} {verdict}")
        if rawm is True:
            match_raw += 1
        elif rawm is False:
            differ += 1
        if isinstance(rawm, bool) and isinstance(strm, bool) and rawm != strm:
            disagreements.append((f, aid, sp))

    print()
    print(f"TOTAL signatures: {len(all_rows)}   raw MATCH: {match_raw}   raw DIFFER: {differ}")
    print("raw-vs-string comparison disagreements:",
          disagreements if disagreements else "none (raw and string verdicts agree on every row)")
    print("[informational only — the pass/fail verdict comes solely from the gate below]")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
                      help="fail-closed read-only gate: render both chains through the "
                           "write path and enforce all six conditions; writes nothing")
    mode.add_argument("--write", action="store_true",
                      help="regenerate both fixtures in place, staging-first: render AND "
                           "validate both chains, then write both (or write neither)")
    args = parser.parse_args(argv)

    # B5: an explicit mode is REQUIRED. A bare invocation is not a pass.
    if not args.check and not args.write:
        parser.print_usage(sys.stderr)
        print("error: exactly one of --check or --write is required; a bare invocation "
              "does nothing and is NOT a pass.", file=sys.stderr)
        return 2

    if args.check:
        # The reproduction table is informational only, and it reads the fixtures
        # directly — so a missing/malformed fixture would crash it (traceback)
        # BEFORE the gate runs, shadowing condition 6. Isolate it: any failure
        # here is reported as "informational unavailable" and execution continues
        # into _run_gate, which is the SOLE verdict and independently re-reads and
        # decides. The table only reads the committed fixtures, and the gate reads
        # them again itself, so a READ/parse failure here cannot mask a fault. The
        # claim is scoped to that: a hypothetical failure that left inconsistent
        # in-process state before the gate ran would not be caught by this swallow.
        try:
            _print_reproduction_table()
        except Exception as e:  # noqa: BLE001 — informational only; the gate decides
            print(f"[informational] reproduction table unavailable ({type(e).__name__}: {e}); "
                  "the fail-closed gate below still runs and decides.", file=sys.stderr)
        print()
        failures, _ = _run_gate("check")
        if failures:
            print(f"\nFAIL — --check found {len(failures)} gate condition(s):", file=sys.stderr)
            for line in failures:
                print("  " + line, file=sys.stderr)
            return 1
        print("\nOK — both lifecycle chains render byte-identically to the committed "
              "fixtures; all six gate conditions pass. No files written.")
        return 0

    # --write: staging-first. Nothing is written unless BOTH chains pass every
    # applicable condition (drift excluded — the write intentionally changes bytes).
    failures, rendered = _run_gate("write")
    if failures:
        print(f"\nFAIL — refusing to write: {len(failures)} gate condition(s):", file=sys.stderr)
        for line in failures:
            print("  " + line, file=sys.stderr)
        print("No fixture was modified.", file=sys.stderr)
        return 1
    for path, _regen in CHAINS:
        path.write_text(rendered[path], encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
