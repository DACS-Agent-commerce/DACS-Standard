#!/usr/bin/env python3
"""Generate complete inputs for the 24 manifest DACS-1/Vet golden cases.

The historical manifest outputs were produced by constructors embedded in the
external dacs-verify runner.  This generator replaces that hidden provenance
with current-wire, signed IdentityBundle and VerifyResult inputs.  It does not
import dacs-verify code or data.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "fixtures" / "identity"
    / "dacs1-vet-golden-inputs-v0.1.json"
)
NOW = 1_900_000_000_000
SOURCE_COMMIT = "ddba42e5789fdde84b4ae1d31eaa4fa65c28965b"
BUNDLE_DOMAIN = "dacs-bundle-presentation:v1:"
RESULT_DOMAIN = "dacs-verifyresult:v1:"


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def hash_hex(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(("dacs-363:" + label).encode("utf-8")).digest()
    )


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


PRESENTER = private_key("presenter")
SECOND_PRESENTER = private_key("second-presenter")
AUTHORITY = private_key("authority")
PRESENTER_REF = f"key:{public_hex(PRESENTER)}"
SECOND_REF = f"key:{public_hex(SECOND_PRESENTER)}"
AUTHORITY_REF = f"key:{public_hex(AUTHORITY)}"
LEI_A = "lei:984500ABCDEF12345678"
LEI_B = "lei:529900T8BM49AABBCC11"


def claim(ref: str, **fields: object) -> dict:
    out = {"ref": ref}
    out.update(copy.deepcopy(fields))
    return out


def requirement(
    required: list[dict],
    *,
    one_of: list[list[dict]] | None = None,
    selector: str | None = None,
) -> dict:
    out = {"requirementVersion": "1", "required": copy.deepcopy(required)}
    if one_of is not None:
        out["oneOf"] = copy.deepcopy(one_of)
    if selector is not None:
        out["primaryClaimSelector"] = selector
    return out


def member(scheme: str, *, verified: bool, max_age: int | None = None) -> dict:
    out = {"scheme": scheme, "verificationRequired": verified}
    if verified:
        out["recipeVersion"] = 1
    if max_age is not None:
        out["maxAge"] = max_age
    return out


def signed_bundle(
    claims: list[dict],
    *,
    presented_by: str | None = None,
    signer: Ed25519PrivateKey = PRESENTER,
    signer_ref: str = PRESENTER_REF,
) -> dict:
    body_claims = copy.deepcopy(claims)
    if not any(item.get("ref") == signer_ref for item in body_claims):
        body_claims.append(claim(signer_ref, issuedAt=NOW - 1_000))
    unsigned = {
        "bundleVersion": "1",
        "presentedBy": presented_by or body_claims[0]["ref"],
        "presentedAt": NOW,
        "claims": body_claims,
    }
    signature = b64url(
        signer.sign((BUNDLE_DOMAIN + hash_hex(unsigned)).encode("ascii"))
    )
    return {
        **unsigned,
        "presentation": {
            "kind": "per-claim",
            "signatures": [{"ref": signer_ref, "signature": signature}],
        },
    }


def signed_result(
    ref: str,
    decision: str,
    label: str,
    *,
    method: str = "vc-presentation",
    verified_at: int = NOW - 1_000,
    valid_until: int = NOW + 60_000,
    data: dict | None = None,
    failure_class: str | None = None,
) -> tuple[dict, dict]:
    scheme, identifier = ref.split(":", 1)
    unsigned = {
        "resultVersion": "1",
        "scheme": scheme,
        "identifier": identifier,
        "recipeVersion": 1,
        "method": method,
        "decision": decision,
        "reason": f"deterministic {label} {decision}",
        "attestation": {
            "anchor": {
                "kind": "storage-program",
                "locator": f"demos:dacs-363:attestation:{label}",
            },
            "contentHash": hashlib.sha256(
                f"dacs-363:{label}:{decision}".encode("utf-8")
            ).hexdigest(),
            "signer": AUTHORITY_REF,
        },
        "fetchedAt": verified_at - 1_000,
        "verifiedAt": verified_at,
        "validUntil": valid_until,
    }
    if data is not None:
        unsigned["data"] = copy.deepcopy(data)
    signature = b64url(
        AUTHORITY.sign((RESULT_DOMAIN + hash_hex(unsigned)).encode("ascii"))
    )
    artifact = {
        **unsigned,
        "signature": {
            "algorithm": "ed25519",
            "signer": AUTHORITY_REF,
            "value": signature,
        },
    }
    result_ref = {
        "anchor": {
            "kind": "storage-program",
            "locator": f"demos:dacs-363:result:{label}",
        },
        "contentHash": hash_hex(unsigned),
        "recipeVersion": 1,
    }
    resolved = {"ref": copy.deepcopy(result_ref), "artifact": artifact}
    if failure_class is not None:
        resolved["failureClass"] = failure_class
    return result_ref, resolved


def verified_claim(
    ref: str,
    decision: str,
    label: str,
    **kwargs: object,
) -> tuple[dict, dict]:
    result_ref, resolved = signed_result(ref, decision, label, **kwargs)
    return claim(ref, issuedAt=NOW - 1_000, verifiedBy=result_ref), resolved


def evaluation(
    operation: str,
    bundle: dict,
    req: dict | None,
    *,
    resolved: list[dict] | None = None,
) -> dict:
    input_value = {
        "evaluatedAt": NOW,
        "bundle": copy.deepcopy(bundle),
        "resolvedResults": copy.deepcopy(resolved or []),
    }
    if req is not None:
        input_value["requirement"] = copy.deepcopy(req)
    return {"operation": operation, "input": input_value}


def add_case(
    cases: list[dict],
    name: str,
    spec: str,
    summary: str,
    evaluations: dict[str, dict],
    expected_output: object,
) -> None:
    replay_input = {"evaluations": copy.deepcopy(evaluations)}
    cases.append({
        "name": name,
        "spec": spec,
        "summary": summary,
        "inputHash": hash_hex(replay_input),
        **replay_input,
        "expectedOutput": copy.deepcopy(expected_output),
    })


def freshness_evaluations(prefix: str) -> dict[str, dict]:
    req = requirement([member("lei", verified=True)])
    max_age_req = requirement([member("lei", verified=True, max_age=60)])

    unavailable_ref = {
        "anchor": {
            "kind": "https",
            "locator": f"https://unavailable.example/{prefix}/result",
        },
        "contentHash": "ab" * 32,
        "recipeVersion": 1,
    }
    absent_bundle = signed_bundle([
        claim(LEI_A, verifiedBy=unavailable_ref),
    ], presented_by=LEI_A)

    expired_claim, expired_result = verified_claim(
        LEI_A, "pass", f"{prefix}-expired", method="gleif-registry"
    )
    expired_claim["expiresAt"] = NOW - 1
    expired_bundle = signed_bundle([expired_claim], presented_by=LEI_A)

    expires_claim, expires_result = verified_claim(
        LEI_A, "pass", f"{prefix}-expires-only", method="gleif-registry"
    )
    expires_claim.pop("issuedAt")
    expires_claim["expiresAt"] = NOW + 60_000
    expires_bundle = signed_bundle([expires_claim], presented_by=LEI_A)

    aged_claim, aged_result = verified_claim(
        LEI_A,
        "pass",
        f"{prefix}-max-age",
        method="gleif-registry",
        verified_at=NOW - 120_000,
        valid_until=NOW + 60_000,
    )
    aged_claim.pop("issuedAt")
    aged_claim["expiresAt"] = NOW + 60_000
    aged_bundle = signed_bundle([aged_claim], presented_by=LEI_A)

    stale_claim, stale_result = verified_claim(
        LEI_A,
        "pass",
        f"{prefix}-selected-stale",
        method="vlei-presentation",
        data={"holderBinding": {"controller": PRESENTER_REF}},
    )
    stale_claim["expiresAt"] = NOW - 1
    fresh_claim, fresh_result = verified_claim(
        LEI_B, "pass", f"{prefix}-other-fresh", method="gleif-registry"
    )
    stale_bundle = signed_bundle(
        [stale_claim, fresh_claim], presented_by=LEI_A
    )
    selected_req = requirement(
        [member("lei", verified=True, max_age=60)], selector="lei"
    )

    return {
        "absentBoth": evaluation("match", absent_bundle, req),
        "expired": evaluation(
            "match", expired_bundle, req, resolved=[expired_result]
        ),
        "expiresOnly": evaluation(
            "match", expires_bundle, req, resolved=[expires_result]
        ),
        "expiresOnlyMaxAge": evaluation(
            "match", aged_bundle, max_age_req, resolved=[aged_result]
        ),
        "stalePresentedByPrimary": evaluation(
            "match",
            stale_bundle,
            selected_req,
            resolved=[stale_result, fresh_result],
        ),
    }


def build_cases() -> list[dict]:
    cases: list[dict] = []

    cci_claim, cci_result = verified_claim(
        "cci-lei:984500ABCDEF12345678",
        "pass",
        "cci-lei-pass",
        method="vc-presentation",
    )
    cci_bundle = signed_bundle(
        [cci_claim], presented_by="cci-lei:984500ABCDEF12345678"
    )
    add_case(
        cases,
        "dacs1-cci-lei-defect",
        "§6.3.3",
        "A cci-lei claim cannot satisfy a distinct bare lei requirement.",
        {"result": evaluation(
            "match", cci_bundle, requirement([member("lei", verified=True)]),
            resolved=[cci_result],
        )},
        False,
    )
    add_case(
        cases,
        "dacs1-cci-lei-named-matches",
        "§6.3.1",
        "The same signed cci-lei claim satisfies its own registered scheme.",
        {"result": evaluation(
            "match",
            cci_bundle,
            requirement([member("cci-lei", verified=True)]),
            resolved=[cci_result],
        )},
        True,
    )

    selected_fail, selected_fail_result = verified_claim(
        LEI_A, "fail", "laundering-selected", method="gleif-registry"
    )
    other_pass, other_pass_result = verified_claim(
        LEI_B, "pass", "laundering-other", method="gleif-registry"
    )
    laundering_bundle = signed_bundle(
        [selected_fail, other_pass], presented_by=LEI_A
    )
    add_case(
        cases,
        "dacs1-tier-laundering-guard",
        "§6.3.3",
        "Another same-scheme pass cannot authorize the exact selected claim.",
        {"result": evaluation(
            "match",
            laundering_bundle,
            requirement([member("lei", verified=True)], selector="lei"),
            resolved=[selected_fail_result, other_pass_result],
        )},
        False,
    )

    registry_claim, registry_result = verified_claim(
        LEI_A, "pass", "registry-lei", method="gleif-registry"
    )
    supporting_bundle = signed_bundle([registry_claim], presented_by=PRESENTER_REF)
    registry_primary_bundle = signed_bundle([registry_claim], presented_by=LEI_A)
    verified_lei = requirement([member("lei", verified=True)])
    selected_lei = requirement([member("lei", verified=True)], selector="lei")
    add_case(
        cases,
        "vet-control-existence-only-lei-supporting-context",
        "§6.3.2 step (6)",
        "A registry pass is valid supporting evidence when the LEI is not used as control.",
        {"result": evaluation(
            "decision", supporting_bundle, verified_lei, resolved=[registry_result]
        )},
        "pass",
    )
    add_case(
        cases,
        "vet-control-existence-only-lei-presentedby-reject",
        "§6.3.2 step (6)",
        "The same existence-only result cannot control the selected LEI.",
        {"result": evaluation(
            "decision", registry_primary_bundle, selected_lei,
            resolved=[registry_result],
        )},
        "fail",
    )
    add_case(
        cases,
        "vet-control-existence-only-lei-reputation-key-reject",
        "§10.5.2",
        "An existence-only LEI cannot be used as a controlled reputation key.",
        {"result": evaluation(
            "control-decision", registry_primary_bundle, None,
            resolved=[registry_result],
        )},
        "fail",
    )

    forged_claim, forged_result = verified_claim(
        LEI_A,
        "pass",
        "registry-forged-holder-binding",
        method="gleif-registry",
        data={"holderBinding": {"controller": PRESENTER_REF}},
    )
    forged_bundle = signed_bundle([forged_claim], presented_by=LEI_A)
    add_case(
        cases,
        "vet-control-existence-method-forged-holderbinding-reject",
        "§6.3.2 step (6)",
        "Data cannot upgrade an existence-only method into a control method.",
        {"result": evaluation(
            "decision", forged_bundle, selected_lei, resolved=[forged_result]
        )},
        "fail",
    )

    key_bundle = signed_bundle(
        [claim(PRESENTER_REF, issuedAt=NOW - 1_000)],
        presented_by=PRESENTER_REF,
    )
    presence_key = requirement([member("key", verified=False)], selector="key")
    add_case(
        cases,
        "vet-control-key-presentation-accept",
        "§6.3.2 step (6)",
        "A lowercase-hex key claim is controlled by its exact bundle signature.",
        {"result": evaluation("decision", key_bundle, presence_key)},
        "pass",
    )

    malformed_bundle = copy.deepcopy(key_bundle)
    malformed_bundle["presentedAt"] = 9_007_199_254_740_992
    add_case(
        cases,
        "vet-control-key-malformed-scope-reject-no-throw",
        "§6.3.2 step (6)/§7.5.1",
        "An unsafe integer in signed scope is an error and never an exception.",
        {"result": evaluation(
            "decision-no-throw", malformed_bundle, presence_key
        )},
        {"decision": "error", "throws": False},
    )

    unavailable_ref = {
        "anchor": {
            "kind": "https",
            "locator": "https://unavailable.example/key-control/result",
        },
        "contentHash": "cd" * 32,
        "recipeVersion": 1,
    }
    unavailable_bundle = signed_bundle([
        claim(PRESENTER_REF, issuedAt=NOW - 1_000, verifiedBy=unavailable_ref),
    ], presented_by=PRESENTER_REF)
    add_case(
        cases,
        "vet-control-key-unresolvable-binding-indeterminate",
        "§6.3.2 step (6)/§7.5.1",
        "An unavailable required key-binding result remains indeterminate.",
        {"result": evaluation(
            "decision",
            unavailable_bundle,
            requirement([member("key", verified=True)]),
        )},
        "indeterminate",
    )

    stale_bundle = signed_bundle([
        claim(PRESENTER_REF, issuedAt=NOW - 2_000, expiresAt=NOW - 1_000),
        claim(SECOND_REF, issuedAt=NOW - 1_000),
    ], presented_by=PRESENTER_REF)
    add_case(
        cases,
        "vet-control-key-stale-reject",
        "§6.3.2 step (6)",
        "A valid key signature cannot make its expired selected claim current.",
        {"result": evaluation("decision", stale_bundle, presence_key)},
        "fail",
    )

    second_claim, second_result = verified_claim(
        SECOND_REF, "pass", "other-key-pass", method="self-signed"
    )
    key_laundering_bundle = signed_bundle([
        claim(PRESENTER_REF, issuedAt=NOW - 1_000), second_claim,
    ], presented_by=PRESENTER_REF)
    add_case(
        cases,
        "vet-control-key-verified-selector-laundering-reject",
        "§6.3.2 step (6)",
        "A different verified key cannot satisfy a verified selector for presentedBy.",
        {"result": evaluation(
            "decision",
            key_laundering_bundle,
            requirement([member("key", verified=True)], selector="key"),
            resolved=[second_result],
        )},
        "fail",
    )

    freshness_expected = {
        "absentBoth": False,
        "expired": False,
        "expiresOnly": True,
        "expiresOnlyMaxAge": False,
        "stalePresentedByPrimary": False,
    }
    add_case(
        cases,
        "dacs1-freshness-fail-closed",
        "§6.3.2/§6.3.3",
        "Verified claims use resolved authority time, clamp expiresAt, and fail closed on unavailable time evidence.",
        freshness_evaluations("dacs1-freshness"),
        freshness_expected,
    )

    did_claim, did_result = verified_claim(
        "did:example:missing-lei", "pass", "missing-required-lei"
    )
    missing_bundle = signed_bundle([did_claim], presented_by=PRESENTER_REF)
    add_case(
        cases,
        "vet-ma1-required-missing",
        "§6.3.3",
        "A signed bundle without the required scheme is rejected.",
        {"result": evaluation(
            "match", missing_bundle, verified_lei, resolved=[did_result]
        )},
        False,
    )

    finra_claim, finra_result = verified_claim(
        "finra-crd:12345", "pass", "oneof-finra", method="vc-presentation"
    )
    satisfied_bundle = signed_bundle([finra_claim], presented_by=PRESENTER_REF)
    unsatisfied_bundle = signed_bundle([did_claim], presented_by=PRESENTER_REF)
    oneof_req = requirement([], one_of=[[
        member("lei", verified=True), member("finra-crd", verified=True),
    ]])
    add_case(
        cases,
        "vet-ma1-oneof",
        "§6.3.3",
        "OneOf passes with a matching member and fails when no member is present.",
        {
            "satisfied": evaluation(
                "match", satisfied_bundle, oneof_req, resolved=[finra_result]
            ),
            "unsatisfied": evaluation(
                "match", unsatisfied_bundle, oneof_req, resolved=[did_result]
            ),
        },
        {"satisfied": True, "unsatisfied": False},
    )

    lei_claim, lei_result = verified_claim(
        LEI_A, "pass", "scheme-mismatch-lei", method="vlei-presentation",
        data={"holderBinding": {"controller": PRESENTER_REF}},
    )
    mismatch_bundle = signed_bundle([lei_claim], presented_by=PRESENTER_REF)
    add_case(
        cases,
        "vet-ma2-scheme-mismatch",
        "§6.3.3",
        "The exact presentedBy scheme must equal primaryClaimSelector.",
        {"result": evaluation(
            "match", mismatch_bundle, selected_lei, resolved=[lei_result]
        )},
        False,
    )

    add_case(
        cases,
        "vet-ma3-unverified-reject",
        "§6.3.3",
        "A failing selected claim is not laundered by another same-scheme pass.",
        {"result": evaluation(
            "match", laundering_bundle, selected_lei,
            resolved=[selected_fail_result, other_pass_result],
        )},
        False,
    )
    add_case(
        cases,
        "vet-ma3-resolution-vs-presence",
        "§6.3.3",
        "Presence can match without resolving an optional failure; verified use cannot.",
        {
            "dacs1Presence": evaluation(
                "match",
                laundering_bundle,
                requirement([member("lei", verified=False)]),
                resolved=[selected_fail_result, other_pass_result],
            ),
            "vetResolved": evaluation(
                "match", laundering_bundle, selected_lei,
                resolved=[selected_fail_result, other_pass_result],
            ),
        },
        {"dacs1Presence": True, "vetResolved": False},
    )

    controlled_lei_claim, controlled_lei_result = verified_claim(
        LEI_A,
        "pass",
        "selected-vlei-pass",
        method="vlei-presentation",
        data={"holderBinding": {"controller": PRESENTER_REF}},
    )
    controlled_lei_bundle = signed_bundle(
        [controlled_lei_claim], presented_by=LEI_A
    )
    add_case(
        cases,
        "vet-ma3-verified-accept",
        "§6.3.3",
        "A fresh selected vLEI result with holder binding is accepted.",
        {"result": evaluation(
            "match", controlled_lei_bundle, selected_lei,
            resolved=[controlled_lei_result],
        )},
        True,
    )

    indet_claim, indet_result = verified_claim(
        LEI_A, "indeterminate", "findclaim-indeterminate",
        method="gleif-registry",
    )
    indet_bundle = signed_bundle([indet_claim], presented_by=PRESENTER_REF)
    add_case(
        cases,
        "vet-findclaim-decision",
        "§6.3.3",
        "An indeterminate required claim does not count as a matching pass.",
        {"result": evaluation(
            "match", indet_bundle, verified_lei, resolved=[indet_result]
        )},
        False,
    )

    add_case(
        cases,
        "vet-freshness-fail-closed",
        "§6.3.2/§6.3.3",
        "Vet applies the same resolved authority window and presenter clamp.",
        freshness_evaluations("vet-freshness"),
        freshness_expected,
    )

    oneof_lei_fail, oneof_lei_fail_result = verified_claim(
        LEI_A, "fail", "oneof-lei-fail", method="gleif-registry"
    )
    domain_error, domain_error_result = verified_claim(
        "domain:example.com",
        "error",
        "oneof-domain-error",
        method="demos-gcr-domain",
        failure_class="transient",
    )
    error_bundle = signed_bundle(
        [oneof_lei_fail, domain_error], presented_by=PRESENTER_REF
    )
    aggregation_oneof = requirement([], one_of=[[
        member("lei", verified=True), member("domain", verified=True),
    ]])
    add_case(
        cases,
        "vet-oneof-error-over-fail",
        "§7.7.1",
        "Within oneOf, retryable error outranks a conclusive failing alternative.",
        {"result": evaluation(
            "aggregate", error_bundle, aggregation_oneof,
            resolved=[oneof_lei_fail_result, domain_error_result],
        )},
        {"decision": "error", "errorClass": "transient"},
    )

    domain_indet, domain_indet_result = verified_claim(
        "domain:example.com",
        "indeterminate",
        "oneof-domain-indeterminate",
        method="demos-gcr-domain",
    )
    indet_oneof_bundle = signed_bundle(
        [oneof_lei_fail, domain_indet], presented_by=PRESENTER_REF
    )
    add_case(
        cases,
        "vet-oneof-indeterminate-over-fail",
        "§7.7.1",
        "Within oneOf, indeterminate outranks fail when no error or pass exists.",
        {"result": evaluation(
            "aggregate", indet_oneof_bundle, aggregation_oneof,
            resolved=[oneof_lei_fail_result, domain_indet_result],
        )},
        {"decision": "indeterminate"},
    )

    cross_req = requirement(
        [member("lei", verified=True)],
        one_of=[[member("domain", verified=True)]],
    )
    add_case(
        cases,
        "vet-cross-accumulator-fail-over-error",
        "§7.7.1",
        "A required hard fail outranks a separate oneOf error globally.",
        {"result": evaluation(
            "aggregate", error_bundle, cross_req,
            resolved=[oneof_lei_fail_result, domain_error_result],
        )},
        {"decision": "fail", "errorClass": "permanent"},
    )

    assert len(cases) == 24
    assert len({case["name"] for case in cases}) == 24
    return cases


def build_document() -> dict:
    cases = build_cases()
    return {
        "set": "dacs1-vet-golden-inputs-v0.1",
        "spec": "DACS-1 §6.3.2/§6.3.3; DACS-2 §7.5.1/§7.7.1",
        "status": "golden",
        "sourceObservation": {
            "repository": "github.com/mj-deving/dacs-verify",
            "commit": SOURCE_COMMIT,
            "path": "conformance/run.ts",
        },
        "provenance": (
            "Standard-owned deterministic reconstruction of the external runner's "
            "previously hidden inputs, normalized to current ClaimReference, "
            "IdentityBundle, VerifyResultRef, signature, freshness, and presence-only rules"
        ),
        "hashScope": (
            "SHA-256 of UTF-8 compact JSON with recursively sorted keys; each inputHash "
            "covers only that case's evaluations; fileSha256 is pinned by MANIFEST.json"
        ),
        "publicTestSeeds": {
            "derivation": "sha256(UTF8('dacs-363:' + label))",
            "labels": ["presenter", "second-presenter", "authority"],
        },
        "publicKeys": {
            "presenter": PRESENTER_REF,
            "secondPresenter": SECOND_REF,
            "authority": AUTHORITY_REF,
        },
        "count": len(cases),
        "hash": hash_hex(cases),
        "cases": cases,
    }


def rendered() -> str:
    return json.dumps(build_document(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.write:
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != expected:
        print(
            "dacs1/vet golden inputs are stale; run "
            "python3 scripts/generate_dacs1_vet_golden_inputs.py --write"
        )
        return 1
    print("dacs1/vet golden inputs OK (24 cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
