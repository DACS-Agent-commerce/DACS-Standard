#!/usr/bin/env python3
"""Validate DACS conformance vector files.

This is intentionally stdlib-only so implementers can run it from a clean clone:

    python3 scripts/validate_conformance_vectors.py
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
import specsource  # noqa: E402
import jcs  # noqa: E402 — stdlib-only RFC 8785 canonicaliser (this repo)

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover — CI installs cryptography before this runs
    HAVE_CRYPTO = False
DEFAULT_VECTOR_DIR = ROOT / "conformance" / "vectors"
DEFAULT_MANIFEST = ROOT / "conformance" / "MANIFEST.json"
EXPECTED_STAGES = ["DACS-1", "DACS-2", "DACS-3", "DACS-4", "DACS-5"]
MANIFEST_REQUIRED_CASE = {"id", "area", "spec", "summary", "status", "want"}
MANIFEST_STATUSES = {"golden", "candidate"}
REGISTRY_CASE_ID = "sig-registry-closed"
GOLDEN_DECISIONS = {"pass", "fail", "indeterminate", "error"}
REQUIRED_TOP_LEVEL = {
    "vectorId",
    "title",
    "dacsVersion",
    "description",
    "artifacts",
    "expectedResult",
}
REQUIRED_ARTIFACT = {
    "id",
    "stage",
    "kind",
    "specRefs",
    "domainSeparator",
    "artifact",
    "contentHash",
}
DOMAIN_RE = re.compile(r'"(dacs[-a-z0-9]*:v1:)"')

# Per-kind fields excluded from the §B.2 canonical form before hashing — each
# kind's "hash-excluded field(s)" from the CORE §B.2 per-artifact template.
HASH_EXCLUDED = {
    "Listing": {"signature"},                              # §B.2
    "CompositeVerificationRecord": {"signature"},          # §B.2 / §7.7
    "AgreementDocument": {"signatures"},                   # DACS-3 §8.5 (L463: "omitting the `signatures` field")
    "SettlementEvidence": {"signature"},                   # §B.2 / §9.7
    "AttestationBundle": {"signatures", "anchoredByRole"}, # DACS-5 §10.4.1 (signatures AND anchoredByRole)
}

# Kind -> §B.7 domain separator. The name is confirmed present in the closed
# §B.7 registry at run time (load_registered_domain_separators), so the payload
# separator is registry-validated, never trusted as supplied by the vector.
KIND_SEPARATOR = {
    "Listing": "dacs-listing:v1:",
    "CompositeVerificationRecord": "dacs-composite:v1:",
    "AgreementDocument": "dacs-agreement:v1:",
    "SettlementEvidence": "dacs-evidence:v1:",
    "AttestationBundle": "dacs-bundle:v1:",
}

# The two lifecycle chains the generator (and write_vectors) regenerate end-to-end.
# This is a FILE-SET for regeneration — deliberately distinct from the padded-Base64
# allowlist below, which they used to share (a conflation removed in the SIG-6 migration).
LIFECYCLE_VECTOR_FILES = {
    "dacs-v0.1-happy-path.json",
    "dacs-v0.1-negative-paths.json",
}

# Padded standard Base64 is accepted only under a DUAL gate: the basename is in this
# allowlist AND the file itself declares the legacy spelling via the top-level
# signatureValueSpelling field below. Either alone is rejected; every other file must
# carry canonical SIG-6 unpadded Base64URL. Canonical SIG-6 is attempted FIRST, so a
# SIG-6 file never requests this permit — which is why the lifecycle chains, now migrated
# to SIG-6, are NO LONGER listed here. The mechanism stays live for any genuine legacy
# padded-Base64 vector; its load-bearing behaviour is exercised by
# tests/test_validate_conformance_vectors.py::test_legacy_base64_dual_gate against a
# constructed specimen carrying the synthetic basename below (no such file is committed —
# an allowlist is a set of permitted names, not a claim that the files exist).
LEGACY_SIG_SPELLING_FILES = {
    "legacy-padded-spelling-fixture.json",
}
LEGACY_SIG_SPELLING_VALUE = "legacy-padded-base64"

# The signature-suite wire spelling this validator can execute. The normative enum
# is `"ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"` (lowercase) — the signature
# envelope shapes in DACS-1/3/4/5 (e.g. spec/DACS-3-NEGOTIATE.md AgreementSignature,
# spec/DACS-5-VERIFY.md BundleSignature). This verifier implements only ed25519; a
# signature declaring any other (or absent/misspelled) suite is recorded "fail"
# because this verifier cannot confirm it, never crashed and never silently passed.
ED25519_ALGORITHM = "ed25519"

# A signatureChecks pin has exactly these keys. Unknown keys are rejected
# (fail-closed): a typo'd or smuggled key must not pass unread.
PIN_KEYS = {"path", "signer", "expect"}
PIN_EXPECT_VALUES = {"verify", "fail"}


def legacy_spelling_allowed(path: Path, data: dict) -> bool:
    """Dual gate for padded standard-Base64 signature values."""
    return (
        path.name in LEGACY_SIG_SPELLING_FILES
        and data.get("signatureValueSpelling") == LEGACY_SIG_SPELLING_VALUE
    )


def load_registered_domain_separators(root: Path = ROOT) -> set[str]:
    spec_text = specsource.spec_text(root)
    start_marker = "The v0.x registry of domain separators at this revision is closed:"
    end_marker = "**Payload shape — single-hash vs composite.**"
    start = spec_text.find(start_marker)
    end = spec_text.find(end_marker, start)
    if start == -1 or end == -1:
        return set()
    return set(DOMAIN_RE.findall(spec_text[start:end]))


def canonical_json(value: Any) -> bytes:
    """§B.2 canonical bytes of ``value``, for the JSON subset these artifacts occupy.

    Delegates to the stdlib-only ``jcs`` module (RFC 8785 over integers, strings,
    literals, arrays, objects — see its docstring) so the artifact hash is the JCS
    serialisation rather than ``json.dumps``. Per CF-1 the module NFC-normalises
    string *values* only; member names are serialised and UTF-16-sorted as received.
    Finite binary64 fractions are supported; numbers outside the DACS magnitude
    bound fail closed.
    """

    return jcs.canonicalize(value).encode("utf-8")


def signing_scope(kind: str, artifact: dict) -> dict:
    """Copy of ``artifact`` with the kind's §B.2 hash-excluded field(s) removed.

    Removal-based, so unrecognised fields stay in the hashed scope (SIG-5
    preserve-unknown). An unknown kind raises: a signable artifact with no declared
    exclusion set must fail closed, never be hashed with its signature left in scope.
    """

    if kind not in HASH_EXCLUDED:
        raise ValueError(f"unknown artifact kind for §B.2 hashing: {kind!r}")
    excluded = HASH_EXCLUDED[kind]
    return {key: value for key, value in artifact.items() if key not in excluded}


def artifact_hash_hex(kind: str, artifact: dict) -> str:
    """64-char lowercase hex sha256 of the §B.2 canonical form (§B.7 ``artifact_hash``)."""
    return hashlib.sha256(canonical_json(signing_scope(kind, artifact))).hexdigest()


def content_hash_uri(kind: str, artifact: dict) -> str:
    """The published envelope form ``"sha256:" + artifact_hash_hex`` (§B.2 content hash)."""
    return "sha256:" + artifact_hash_hex(kind, artifact)


def _is_canonical_sig6(value: str) -> bool:
    """True when ``value`` is canonical SIG-6 unpadded Base64URL (CORE §B.7 SIG-6)."""
    if not value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        return False
    # SIG-6: compare the value against an unpadded Base64URL re-encoding of its bytes.
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value


def decode_signature_value(value: Any, legacy_allowed: bool) -> bytes:
    """Decode a signature ``value`` to raw bytes. Canonical SIG-6 first; padded
    standard Base64 accepted only when ``legacy_allowed`` (the dual gate: an
    allowlisted basename AND the file's own signatureValueSpelling declaration)."""
    if not isinstance(value, str):
        raise ValueError("signature value must be a string")
    if _is_canonical_sig6(value):
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if legacy_allowed:
        return base64.b64decode(value, validate=True)  # padded standard Base64 (documented legacy)
    raise ValueError("signature value is not canonical SIG-6 unpadded Base64URL")


def _pubkey_from_claim(claim: Any):
    scheme, _, identifier = str(claim).partition(":")
    if scheme != "cci" or re.fullmatch(r"[0-9a-f]{64}", identifier) is None:
        raise ValueError(f"cannot resolve signer key from claim {claim!r}")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(identifier))


def signature_entries(artifact: dict) -> list:
    """[(path, envelope), ...] for the artifact's top-level signature field(s)."""
    if "signature" in artifact:
        return [("signature", artifact["signature"])]
    return [(f"signatures[{i}]", s) for i, s in enumerate(artifact.get("signatures", []))]


def observed_signature_checks(kind: str, artifact: dict, registry: set, legacy_allowed: bool) -> list:
    """Verify each top-level signature; return observed pins in artifact order,
    each ``{"path", "signer", "expect": "verify"|"fail"}``.

    Payload is the registry-validated §B.7 ``separator || artifact_hash_hex`` (the
    ASCII hex string, not raw digest bytes). This is executed verification, not a
    claim: an ed25519 signature succeeding under exactly this separator string is
    empirical proof the separator is byte-identical to what the signer used.
    """

    separator = KIND_SEPARATOR[kind]
    if separator not in registry:
        raise ValueError(f"{kind} separator {separator!r} is not in the closed §B.7 registry")
    payload = (separator + artifact_hash_hex(kind, artifact)).encode("ascii")
    results = []
    for path, envelope in signature_entries(artifact):
        envelope = envelope if isinstance(envelope, dict) else {}
        signer = envelope.get("signer") or envelope.get("party")
        outcome = "fail"
        # Bind the declared suite: only ed25519 is executable here. A different,
        # absent, or misspelled algorithm is recorded "fail" (unverifiable under
        # this verifier), never a silent verify and never a crash.
        if envelope.get("algorithm") == ED25519_ALGORITHM:
            try:
                _pubkey_from_claim(signer).verify(
                    decode_signature_value(envelope["value"], legacy_allowed), payload
                )
                outcome = "verify"
            except (InvalidSignature, ValueError, KeyError, TypeError):
                outcome = "fail"
        results.append({"path": path, "signer": signer, "expect": outcome})
    return results


def _pin_key(pin: dict) -> tuple:
    return (pin.get("path"), pin.get("signer"), pin.get("expect"))


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def fail(path: Path, message: str) -> str:
    return f"{display_path(path)}: {message}"


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def fixture_exists(manifest_dir: Path, fixture: str) -> bool:
    """Return true when a fixture path exists relative to common vector roots.

    PR #117-style golden outputs use repository-root paths such as
    `conformance/fixtures/example.json`, while smaller local harness tests may use
    manifest-relative paths such as `fixtures/example.json`. Accept both so the
    structural validator composes with either layout without rewriting vectors.
    Absolute paths and traversal outside those roots are rejected.
    """

    fixture_path = Path(fixture)
    if fixture_path.is_absolute():
        return False

    allowed_roots = [manifest_dir, manifest_dir.parent]
    candidates = [manifest_dir / fixture_path, manifest_dir.parent / fixture_path]
    return any(
        candidate.is_file() and is_within(candidate, root)
        for candidate, root in zip(candidates, allowed_roots)
    )


def validate_vector(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [fail(path, f"invalid JSON: {exc}")]

    if not isinstance(data, dict):
        return [fail(path, "top-level value MUST be an object")]

    missing = sorted(REQUIRED_TOP_LEVEL - set(data))
    if missing:
        errors.append(fail(path, f"missing top-level keys: {', '.join(missing)}"))

    if data.get("dacsVersion") != "0.1":
        errors.append(fail(path, "dacsVersion MUST be '0.1' for this vector set"))

    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append(fail(path, "artifacts MUST be a non-empty array"))
        return errors

    stages = []
    artifact_ids = set()
    signature_expectations: list[str] = []
    legacy_allowed = legacy_spelling_allowed(path, data)
    for idx, artifact in enumerate(artifacts):
        prefix = f"artifact[{idx}]"
        if not isinstance(artifact, dict):
            errors.append(fail(path, f"{prefix} MUST be an object"))
            continue

        missing_artifact = sorted(REQUIRED_ARTIFACT - set(artifact))
        if missing_artifact:
            errors.append(fail(path, f"{prefix} missing keys: {', '.join(missing_artifact)}"))
            continue

        artifact_id = artifact["id"]
        if artifact_id in artifact_ids:
            errors.append(fail(path, f"duplicate artifact id: {artifact_id}"))
        artifact_ids.add(artifact_id)

        stage = artifact["stage"]
        stages.append(stage)
        if stage not in EXPECTED_STAGES:
            errors.append(fail(path, f"{artifact_id}: unknown stage {stage!r}"))

        refs = artifact["specRefs"]
        if not isinstance(refs, list) or not refs or not all(isinstance(ref, str) and ref.startswith("§") for ref in refs):
            errors.append(fail(path, f"{artifact_id}: specRefs MUST be non-empty § references"))

        separator = artifact["domainSeparator"]
        registry = load_registered_domain_separators(ROOT)
        if not isinstance(separator, str) or not separator.endswith(":v1:"):
            errors.append(fail(path, f"{artifact_id}: domainSeparator SHOULD end with ':v1:'"))
        elif registry and separator not in registry:
            errors.append(fail(path, f"{artifact_id}: domainSeparator is not registered in §7.7: {separator}"))

        kind = artifact["kind"]
        if kind not in HASH_EXCLUDED:
            errors.append(fail(path, f"{artifact_id}: unknown artifact kind {kind!r} (no §B.2 hash-exclusion rule)"))
            continue

        # Bind the declared domainSeparator to the kind's registry-validated §B.7
        # separator — the same string the signature payload is built from. Without
        # this, a vector could advertise one separator and be verified under another.
        expected_separator = KIND_SEPARATOR[kind]
        if artifact["domainSeparator"] != expected_separator:
            errors.append(
                fail(
                    path,
                    f"{artifact_id}: domainSeparator {artifact['domainSeparator']!r} does not match "
                    f"the {kind} §B.7 separator {expected_separator!r}",
                )
            )

        # §B.2 envelope content hash over the signature-omitted canonical form.
        expected_hash = content_hash_uri(kind, artifact["artifact"])
        if artifact["contentHash"] != expected_hash:
            errors.append(
                fail(
                    path,
                    f"{artifact_id}: contentHash mismatch; expected {expected_hash}, got {artifact['contentHash']}",
                )
            )

        # Executed ed25519 verification of every embedded signature, pinned two-way.
        declared = artifact.get("signatureChecks")
        if not isinstance(declared, list) or not declared:
            errors.append(fail(path, f"{artifact_id}: signatureChecks MUST be a non-empty array of signature pins"))
        elif not all(isinstance(pin, dict) for pin in declared):
            errors.append(fail(path, f"{artifact_id}: every signatureChecks entry MUST be an object"))
        else:
            # Validate each pin's shape BEFORE _pin_key/sort, so a malformed pin
            # produces a clear error rather than a TypeError from sorting None keys.
            pin_errors = []
            for i, pin in enumerate(declared):
                unknown = set(pin) - PIN_KEYS
                if unknown:
                    pin_errors.append(f"pin[{i}] has unknown keys: {sorted(unknown)}")
                if not isinstance(pin.get("path"), str) or not pin.get("path"):
                    pin_errors.append(f"pin[{i}].path MUST be a non-empty string")
                if not isinstance(pin.get("signer"), str) or not pin.get("signer"):
                    pin_errors.append(f"pin[{i}].signer MUST be a non-empty string")
                if pin.get("expect") not in PIN_EXPECT_VALUES:
                    pin_errors.append(f"pin[{i}].expect MUST be one of: {sorted(PIN_EXPECT_VALUES)}")
            if pin_errors:
                for message in pin_errors:
                    errors.append(fail(path, f"{artifact_id}: {message}"))
            else:
                observed = observed_signature_checks(kind, artifact["artifact"], registry, legacy_allowed)
                declared_ms = sorted(_pin_key(pin) for pin in declared)
                observed_ms = sorted(_pin_key(pin) for pin in observed)
                if declared_ms != observed_ms:
                    errors.append(
                        fail(
                            path,
                            f"{artifact_id}: signatureChecks mismatch; declared {declared_ms} but observed {observed_ms}",
                        )
                    )
                signature_expectations.extend(pin.get("expect") for pin in declared)

    if stages != EXPECTED_STAGES:
        errors.append(fail(path, f"artifacts MUST cover stages in order: {EXPECTED_STAGES}; got {stages}"))

    expected = data.get("expectedResult", {})
    if not isinstance(expected, dict) or not isinstance(expected.get("verifies"), bool):
        errors.append(fail(path, "expectedResult.verifies MUST be a boolean"))
    elif expected.get("verifies") is False:
        failures = expected.get("expectedFailures")
        if not isinstance(failures, list) or not failures:
            errors.append(fail(path, "negative-path vectors MUST list expectedResult.expectedFailures"))

    # File coherence: a positive vector (verifies:true) MUST NOT carry a
    # signature-failure pin. The converse deliberately does NOT hold — a negative
    # vector may fail on purely semantic grounds (HTLC preimage, artifact shape,
    # reference resolution) with every signature valid, so signature assertions
    # live only in the per-artifact pins and are never inferred from expectedResult.
    verifies = expected.get("verifies") if isinstance(expected, dict) else None
    if verifies is True and any(exp == "fail" for exp in signature_expectations):
        errors.append(fail(path, "expectedResult.verifies is true but a signatureChecks pin expects 'fail'"))

    return errors


def validate_manifest(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [fail(path, "manifest file not found")]
    except json.JSONDecodeError as exc:
        return [fail(path, f"invalid JSON: {exc}")]

    if not isinstance(data, dict):
        return [fail(path, "top-level value MUST be an object")]

    if data.get("dacsVersion") != "0.1":
        errors.append(fail(path, "dacsVersion MUST be '0.1' for this manifest"))

    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append(fail(path, "cases MUST be a non-empty array"))
        return errors

    case_ids: set[str] = set()
    for idx, case in enumerate(cases):
        prefix = f"case[{idx}]"
        if not isinstance(case, dict):
            errors.append(fail(path, f"{prefix} MUST be an object"))
            continue

        missing = sorted(MANIFEST_REQUIRED_CASE - set(case))
        if missing:
            errors.append(fail(path, f"{prefix} missing keys: {', '.join(missing)}"))

        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id:
            errors.append(fail(path, f"{prefix}.id MUST be a non-empty string"))
        elif case_id in case_ids:
            errors.append(fail(path, f"duplicate case id: {case_id}"))
        else:
            case_ids.add(case_id)

        for key in ["area", "spec", "summary", "status"]:
            value = case.get(key)
            if not isinstance(value, str) or not value:
                errors.append(fail(path, f"{prefix}.{key} MUST be a non-empty string"))

        spec = case.get("spec")
        if isinstance(spec, str) and spec and not spec.startswith("§"):
            errors.append(fail(path, f"{prefix}.spec MUST start with '§'"))

        status = case.get("status")
        if isinstance(status, str) and status and status not in MANIFEST_STATUSES:
            errors.append(fail(path, f"{prefix}.status MUST be one of: {', '.join(sorted(MANIFEST_STATUSES))}"))

        reason = case.get("reason")
        if status == "golden" and (not isinstance(reason, str) or not reason):
            errors.append(fail(path, f"{prefix}.reason MUST be a non-empty string for golden cases"))

        fixture = case.get("fixture")
        if fixture is not None:
            if not isinstance(fixture, str) or not fixture:
                errors.append(fail(path, f"{prefix}.fixture MUST be a non-empty path string"))
            elif not fixture_exists(path.parent, fixture):
                errors.append(fail(path, f"{prefix}.fixture missing: {fixture}"))

        if case_id == REGISTRY_CASE_ID:
            registry = sorted(load_registered_domain_separators(ROOT))
            want = case.get("want")
            if case.get("spec") != "§B.7":
                errors.append(fail(path, f"{prefix}.spec MUST identify the closed registry at §B.7"))
            if not registry:
                errors.append(fail(path, f"{prefix}: could not parse the closed §B.7 domain-separator registry"))
            elif not isinstance(want, dict):
                errors.append(fail(path, f"{prefix}.want MUST pin the registry count and exact separator set"))
            else:
                if want.get("count") != len(registry):
                    errors.append(
                        fail(
                            path,
                            f"{prefix}.want.count mismatch; expected {len(registry)}, got {want.get('count')!r}",
                        )
                    )
                if want.get("separators") != registry:
                    errors.append(
                        fail(
                            path,
                            f"{prefix}.want.separators MUST equal the sorted closed §B.7 registry",
                        )
                    )

    golden_path = path.parent / "vectors" / "golden.json"
    if golden_path.exists():
        errors.extend(validate_golden_outputs(golden_path, path))

    return errors


def validate_golden_outputs(path: Path, manifest_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [fail(path, f"invalid JSON: {exc}")]

    if not isinstance(data, dict):
        return [fail(path, "top-level value MUST be an object")]

    manifest_dir = manifest_path.parent
    fixture_keys = {
        "bundle": ["fixture", "divergentSellerFixture", "htlc9Fixture"],
        "settlement": ["fixture", "deliveryFixture", "ap2Fixture"],
    }
    for section, keys in fixture_keys.items():
        section_data = data.get(section)
        if section_data is None:
            continue
        if not isinstance(section_data, dict):
            errors.append(fail(path, f"{section} MUST be an object"))
            continue
        for key in keys:
            fixture = section_data.get(key)
            if fixture is None:
                continue
            if not isinstance(fixture, str) or not fixture:
                errors.append(fail(path, f"{section}.{key} MUST be a non-empty fixture path string"))
                continue
            if not fixture_exists(manifest_dir, fixture):
                errors.append(fail(path, f"{section}.{key} missing fixture: {fixture}"))

    for section in ["bundle", "dispute", "disclosure", "settlement"]:
        section_data = data.get(section)
        if section_data is None:
            continue
        if not isinstance(section_data, dict):
            errors.append(fail(path, f"{section} MUST be an object"))
            continue
        decisions = section_data.get("decisions")
        if decisions is None:
            continue
        if not isinstance(decisions, dict):
            errors.append(fail(path, f"{section}.decisions MUST be an object"))
            continue
        for decision_key, decision in decisions.items():
            if decision not in GOLDEN_DECISIONS:
                errors.append(
                    fail(
                        path,
                        f"{section}.decisions.{decision_key} MUST be one of: {', '.join(sorted(GOLDEN_DECISIONS))}",
                    )
                )

    return errors


def iter_vector_files(vector_dir: Path) -> list[Path]:
    return sorted(p for p in vector_dir.glob("*.json") if p.is_file())


# The intentional signature tampers in the lifecycle corpus, declared once as a
# structural set of (signaturePath, artifactId) pairs. Every OTHER stored signature
# must verify; the --write gate derives its expected verify-count from the corpus size
# minus this set, so the count is never a magic number and the set is asserted exactly.
# (The tampered HTLC preimage in neg-settlement-tampered-preimage is a payload-semantics
# defect, NOT a signature tamper — its ed25519 signature over the §B.2 scope still
# verifies — so it is deliberately NOT listed here.)
INTENTIONAL_SIGNATURE_TAMPERS = frozenset({
    ("signatures[0]", "neg-bundle-tampered-signature"),
})


def require_crypto() -> None:
    if not HAVE_CRYPTO:
        raise SystemExit(
            "cryptography is required for signature verification but is not importable; "
            "CI installs it before this validator runs (.github/workflows/validate.yml). "
            "Install it with: python3 -m pip install cryptography"
        )


def write_vectors() -> int:
    """One-shot regeneration gate for #278: regenerate the 10 envelope contentHash
    values AND populate signatureChecks from observed verification, then hard-assert
    the distribution before writing.

    The frozen distribution — 13 pins expecting 'verify' plus exactly ONE expecting
    'fail' at neg-bundle-tampered-signature signatures[0] — is specific to this
    corpus and is EXPECTED to be relaxed or replaced when the corpus legitimately
    changes (notably the external chain regeneration tracked in the #278 follow-up).
    Any other distribution aborts without writing (write-then-check determinism)."""

    require_crypto()
    registry = load_registered_domain_separators(ROOT)
    files = [DEFAULT_VECTOR_DIR / name for name in sorted(LIFECYCLE_VECTOR_FILES)]
    staged: list[tuple[Path, dict]] = []
    total_signatures = 0
    observed_fail_pins: set[tuple[str, str]] = set()
    for path in files:
        data = json.loads(path.read_text(encoding="utf-8"))
        legacy_allowed = legacy_spelling_allowed(path, data)
        for artifact in data["artifacts"]:
            kind = artifact["kind"]
            artifact["contentHash"] = content_hash_uri(kind, artifact["artifact"])
            observed = observed_signature_checks(kind, artifact["artifact"], registry, legacy_allowed)
            artifact["signatureChecks"] = observed
            for pin in observed:
                total_signatures += 1
                if pin["expect"] != "verify":
                    observed_fail_pins.add((pin["path"], artifact["id"]))
        staged.append((path, data))

    # Expectation DERIVED from the corpus, not a literal: every stored signature must
    # verify except exactly the declared intentional-tamper set. This survives Step-5's
    # negative-chain regeneration unchanged, as long as that regeneration keeps the same
    # signature cardinality and the same single tampered bundle signature.
    verify_count = total_signatures - len(observed_fail_pins)
    expected_verify = total_signatures - len(INTENTIONAL_SIGNATURE_TAMPERS)
    if observed_fail_pins != set(INTENTIONAL_SIGNATURE_TAMPERS) or verify_count != expected_verify:
        print(
            "refusing to write: unexpected signature distribution "
            f"(total={total_signatures}, verify={verify_count}, "
            f"observed_fail_pins={sorted(observed_fail_pins)}); expected "
            f"{expected_verify} verify + failures exactly "
            f"{sorted(INTENTIONAL_SIGNATURE_TAMPERS)}",
            file=sys.stderr,
        )
        return 1

    for path, data in staged:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"wrote {display_path(path)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate DACS conformance vector JSON files")
    parser.add_argument("paths", nargs="*", help="Specific five-stage vector files to validate")
    parser.add_argument("--manifest", type=Path, help="PR117-style MANIFEST.json to validate")
    parser.add_argument(
        "--write",
        action="store_true",
        help="Regenerate the lifecycle vectors' contentHash + signatureChecks from observed §B.2 hashes and verification",
    )
    args = parser.parse_args(argv)

    if args.write:
        return write_vectors()

    manifest_path = args.manifest
    if manifest_path is None and not args.paths and DEFAULT_MANIFEST.exists():
        manifest_path = DEFAULT_MANIFEST

    if args.paths:
        paths = [Path(p) for p in args.paths]
    elif args.manifest is not None:
        paths = []
    else:
        paths = iter_vector_files(DEFAULT_VECTOR_DIR)
    if manifest_path is not None:
        golden_path = manifest_path.parent / "vectors" / "golden.json"
        paths = [path for path in paths if path.resolve() != golden_path.resolve()]

    if not paths and manifest_path is None:
        print(f"no vector files found under {DEFAULT_VECTOR_DIR.relative_to(ROOT)}", file=sys.stderr)
        return 1

    if paths:
        require_crypto()  # vector validation executes ed25519 verification

    all_errors: list[str] = []
    for path in paths:
        all_errors.extend(validate_vector(path))
    if manifest_path is not None:
        all_errors.extend(validate_manifest(manifest_path))

    if all_errors:
        print("conformance vector validation failed:", file=sys.stderr)
        for error in all_errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    if paths:
        plural = "s" if len(paths) != 1 else ""
        print(f"validated {len(paths)} vector{plural}")
    if manifest_path is not None:
        print(f"validated manifest: {display_path(manifest_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
