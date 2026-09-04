#!/usr/bin/env python3
"""Generate CORE v0.3 IBH-1..IBH-6 cross-stage binding vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import jcs


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/vectors/security/identity-bundle-hash-binding-v0.1.json"

CLAIM = "cci-lei:984500IBHBUYER00001"
OTHER_CLAIM = "cci-lei:984500IBHSELLER0001"
IDENTITY_BUNDLE_WITHOUT_PRESENTATION = {
    "bundleVersion": "1",
    "presentedBy": CLAIM,
    "presentedAt": 1_800_000_000_000,
    "sessionNonce": "ibh-vector-session-nonce-000000000001",
    "claims": [
        {
            "ref": CLAIM,
            "metadata": {"fixture": "identity-bundle-hash-binding-v0.1"},
        }
    ],
}
DIGEST = hashlib.sha256(
    jcs.canonicalize(IDENTITY_BUNDLE_WITHOUT_PRESENTATION).encode("utf-8")
).hexdigest()
OTHER_DIGEST = "51cd" * 16


def party(bundle_hash: str, *, role: str = "buyer", claim: str = CLAIM) -> dict[str, str]:
    return {"role": role, "primaryClaim": claim, "bundleHash": bundle_hash}


def vector(
    name: str,
    *,
    commitment_type: str = "finality",
    legacy_anchor_authenticated: bool = True,
    agreement_integrity: str = "valid",
    resolved_state: str = "present",
    resolved_role: str = "buyer",
    resolved_claim: str = CLAIM,
    composite_hash: str = DIGEST,
    payment_hash: str = DIGEST,
    agreement_hash: str = DIGEST,
    agreement_role: str = "buyer",
    agreement_claim: str = CLAIM,
    session_hash: str = DIGEST,
    session_role: str = "buyer",
    session_claim: str = CLAIM,
    terminal_hash: str = DIGEST,
    terminal_role: str = "buyer",
    terminal_claim: str = CLAIM,
    expected: str,
    reason: str,
    projected_hash: str | None = None,
    comparison: str | None = None,
    preserves_legacy: bool = False,
    note: str,
) -> dict[str, Any]:
    resolved_bundle = copy.deepcopy(IDENTITY_BUNDLE_WITHOUT_PRESENTATION)
    return {
        "name": name,
        "operation": "validate-identity-bundle-cross-stage-binding",
        "trustedContext": {
            "commitment": {
                "type": commitment_type,
                "legacyAnchorAuthenticated": legacy_anchor_authenticated,
            },
            "agreementIntegrity": agreement_integrity,
            "resolvedIdentityBundle": {
                "state": resolved_state,
                "identityBundleWithoutPresentation": resolved_bundle,
                "role": resolved_role,
                "primaryClaim": resolved_claim,
            },
        },
        "protocolInput": {
            "compositeBundleHash": composite_hash,
            "paymentPayerBundleHash": payment_hash,
            "agreementParty": party(
                agreement_hash, role=agreement_role, claim=agreement_claim
            ),
            "sessionParty": party(session_hash, role=session_role, claim=session_claim),
            "bundleParty": party(
                terminal_hash, role=terminal_role, claim=terminal_claim
            ),
        },
        "expected": expected,
        "want": {
            "authorizedForTerminalClosure": expected == "pass",
            "reason": reason,
            "projectedBundleHash": projected_hash,
            "comparison": comparison,
            "legacyAgreementBytesPreserved": preserves_legacy,
        },
        "rule": "CORE §B.2 IBH-1..IBH-6",
        "note": note,
    }


def build_vectors() -> list[dict[str, Any]]:
    prefixed = "sha256:" + DIGEST
    prefixed_other = "sha256:" + OTHER_DIGEST
    return [
        vector(
            "current-agreement-to-terminal-succeeds",
            expected="pass",
            reason="current-byte-exact-binding",
            projected_hash=DIGEST,
            comparison="byte-exact-current",
            note="Every current stage carries the same bare lowercase digest.",
        ),
        vector(
            "current-agreement-prefixed-rejected",
            agreement_hash=prefixed,
            expected="fail",
            reason="invalid-current-agreement-encoding",
            note="Equal decoded bytes do not make a prefixed current agreement valid.",
        ),
        vector(
            "current-agreement-uppercase-hex-rejected",
            agreement_hash=DIGEST.upper(),
            expected="fail",
            reason="invalid-current-agreement-encoding",
            note="Current hexadecimal is lowercase and is never normalized on read.",
        ),
        vector(
            "current-composite-prefixed-rejected",
            composite_hash=prefixed,
            expected="fail",
            reason="invalid-composite-encoding",
            note="The legacy exception never applies to a DACS-2 composite record.",
        ),
        vector(
            "current-payment-input-prefixed-rejected",
            payment_hash=prefixed,
            expected="fail",
            reason="invalid-payment-encoding",
            note="The legacy exception never applies to a DACS-4 payment-party input.",
        ),
        vector(
            "current-session-prefixed-rejected",
            session_hash=prefixed,
            expected="fail",
            reason="invalid-session-encoding",
            note="SessionParty always uses the current bare form.",
        ),
        vector(
            "current-terminal-prefixed-rejected",
            terminal_hash=prefixed,
            expected="fail",
            reason="invalid-terminal-encoding",
            note="BundleParty always uses the current bare form.",
        ),
        vector(
            "wrong-agreement-digest-rejected",
            agreement_hash=OTHER_DIGEST,
            expected="fail",
            reason="agreement-bundle-digest-mismatch",
            note="A well-encoded but wrong agreement digest cannot bind the resolved bundle.",
        ),
        vector(
            "wrong-composite-digest-rejected",
            composite_hash=OTHER_DIGEST,
            expected="fail",
            reason="composite-bundle-digest-mismatch",
            note="The Vet record must bind the same resolved bundle.",
        ),
        vector(
            "wrong-payment-input-digest-rejected",
            payment_hash=OTHER_DIGEST,
            expected="fail",
            reason="payment-bundle-digest-mismatch",
            note="A payment handler must bind the same resolved bundle before a rail action.",
        ),
        vector(
            "wrong-session-digest-rejected",
            session_hash=OTHER_DIGEST,
            expected="fail",
            reason="session-bundle-digest-mismatch",
            note="Session state cannot substitute a different IdentityBundle.",
        ),
        vector(
            "wrong-terminal-digest-rejected",
            terminal_hash=OTHER_DIGEST,
            expected="fail",
            reason="terminal-bundle-digest-mismatch",
            note="Terminal audit output cannot substitute a different IdentityBundle.",
        ),
        vector(
            "identity-bundle-unavailable-is-indeterminate",
            resolved_state="unavailable",
            expected="indeterminate",
            reason="identity-bundle-unavailable",
            note="Digest strings alone do not replace independent bundle resolution.",
        ),
        vector(
            "legacy-prefixed-agreement-projects-to-bare-terminal",
            commitment_type="legacy",
            agreement_hash=prefixed,
            expected="pass",
            reason="legacy-typed-digest-binding",
            projected_hash=DIGEST,
            comparison="typed-legacy-digest",
            preserves_legacy=True,
            note="Verified legacy agreement bytes remain unchanged while DACS-5 emits bare hex.",
        ),
        vector(
            "legacy-prefixed-agreement-without-anchor-proof-is-indeterminate",
            commitment_type="legacy",
            legacy_anchor_authenticated=False,
            agreement_hash=prefixed,
            expected="indeterminate",
            reason="legacy-context-not-authenticated",
            note="A legacy spelling without authenticated commitment-era context is audit-only.",
        ),
        vector(
            "legacy-prefixed-wrong-digest-rejected",
            commitment_type="legacy",
            agreement_hash=prefixed_other,
            expected="fail",
            reason="agreement-bundle-digest-mismatch",
            note="The typed legacy comparison does not weaken digest equality.",
        ),
        vector(
            "legacy-uppercase-prefix-rejected",
            commitment_type="legacy",
            agreement_hash="SHA256:" + DIGEST,
            expected="fail",
            reason="invalid-legacy-agreement-encoding",
            note="Only the exact frozen lowercase prefix is readable.",
        ),
        vector(
            "legacy-bare-agreement-remains-byte-exact",
            commitment_type="legacy",
            expected="pass",
            reason="current-byte-exact-binding",
            projected_hash=DIGEST,
            comparison="byte-exact-current",
            note="A legacy commitment does not force prefix insertion into an already bare value.",
        ),
        vector(
            "prefix-insertion-invalidates-signed-agreement",
            agreement_integrity="invalid",
            agreement_hash=prefixed,
            expected="fail",
            reason="agreement-integrity-failed",
            note="A reader cannot add the prefix before checking the signed bytes.",
        ),
        vector(
            "prefix-removal-invalidates-signed-legacy-agreement",
            commitment_type="legacy",
            agreement_integrity="invalid",
            expected="fail",
            reason="agreement-integrity-failed",
            note="Projection never rewrites the agreement field covered by its signatures.",
        ),
        vector(
            "agreement-role-substitution-rejected",
            agreement_role="seller",
            expected="fail",
            reason="party-role-mismatch",
            note="Digest equality cannot move a bundle between commercial roles.",
        ),
        vector(
            "terminal-primary-claim-substitution-rejected",
            terminal_claim=OTHER_CLAIM,
            expected="fail",
            reason="party-primary-claim-mismatch",
            note="Digest equality cannot move a bundle to another canonical primary claim.",
        ),
    ]


def document() -> dict[str, Any]:
    vectors = build_vectors()
    encoded = json.dumps(
        vectors, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "set": "identity-bundle-hash-binding-v0.1",
        "spec": "CORE §B.2 IBH-1..IBH-6 cross-stage IdentityBundle digest binding",
        "tier": "candidate",
        "supersedesIdentityBundleHashProfiles": [
            "payee-destination-binding-v0.1"
        ],
        "description": (
            "One bare current digest encoding across DACS-2/3/5 with a typed, "
            "signature-preserving legacy DACS-3 agreement projection."
        ),
        "count": len(vectors),
        "hash": hashlib.sha256(encoded).hexdigest(),
        "vectors": vectors,
    }


def rendered() -> str:
    return json.dumps(document(), ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.write:
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)} ({document()['count']} vectors)")
        return 0
    try:
        actual = OUTPUT.read_text(encoding="utf-8")
    except FileNotFoundError:
        actual = ""
    if actual != expected:
        print("IdentityBundle hash vectors are stale; run with --write")
        return 1
    print(f"IdentityBundle hash vectors OK ({document()['count']} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
