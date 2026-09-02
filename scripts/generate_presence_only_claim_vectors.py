#!/usr/bin/env python3
"""Generate deterministic DACS-1/DACS-2 PCR-1..PCR-6 vectors."""
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
    ROOT / "conformance" / "vectors" / "security"
    / "presence-only-claim-requirement-v0.7.json"
)
NOW = 1_900_000_000_000
BUNDLE_DOMAIN = "dacs-bundle-presentation:v1:"
VERIFY_RESULT_DOMAIN = "dacs-verifyresult:v1:"
COMPOSITE_DOMAIN = "dacs-composite:v1:"


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def hash_hex(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(label.encode("utf-8")).digest()
    )


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


PRESENTER = private_key("dacs-334-presenter")
SECOND_PRESENTER = private_key("dacs-334-second-presenter")
AUTHORITY = private_key("dacs-334-authority")
VERIFIER = private_key("dacs-334-verifier")
PRESENTER_REF = f"key:{public_hex(PRESENTER)}"
SECOND_REF = f"key:{public_hex(SECOND_PRESENTER)}"
AUTHORITY_REF = f"key:{public_hex(AUTHORITY)}"
VERIFIER_REF = f"key:{public_hex(VERIFIER)}"
LEI_REF = "lei:5493001KJTIIGC8Y1R12"
DID_REF = "did:example:presence-vector"


def sign_component(
    unsigned: dict, key: Ed25519PrivateKey, signer: str, domain: str
) -> dict:
    payload = (domain + hash_hex(unsigned)).encode("ascii")
    return {
        **copy.deepcopy(unsigned),
        "signature": {
            "algorithm": "ed25519",
            "signer": signer,
            "value": b64url(key.sign(payload)),
        },
    }


def claim(ref: str, **fields: object) -> dict:
    value = {"ref": ref}
    value.update(copy.deepcopy(fields))
    return value


def signed_bundle(
    claims: list[dict],
    *,
    presented_by: str = PRESENTER_REF,
    signer: Ed25519PrivateKey = PRESENTER,
    signer_ref: str = PRESENTER_REF,
) -> dict:
    unsigned = {
        "bundleVersion": "1",
        "presentedBy": presented_by,
        "presentedAt": NOW - 1_000,
        "claims": copy.deepcopy(claims),
    }
    digest = hash_hex(unsigned)
    signature = b64url(signer.sign((BUNDLE_DOMAIN + digest).encode("ascii")))
    return {
        **unsigned,
        "presentation": {
            "kind": "per-claim",
            "signatures": [{"ref": signer_ref, "signature": signature}],
        },
    }


def verify_result(
    ref: str,
    decision: str,
    *,
    verified_at: int = NOW - 10_000,
    valid_until: int | None = NOW + 3_600_000,
    recipe_version: int = 1,
) -> dict:
    scheme, identifier = ref.split(":", 1)
    unsigned = {
        "resultVersion": "1",
        "scheme": scheme,
        "identifier": identifier,
        "recipeVersion": recipe_version,
        "method": "self-signed",
        "decision": decision,
        "reason": f"deterministic {decision} vector",
        "attestation": {
            "anchor": {
                "kind": "storage-program",
                "locator": "demos:presence-vector:attestation",
            },
            "contentHash": hashlib.sha256(
                f"attestation:{ref}:{decision}:{verified_at}".encode("utf-8")
            ).hexdigest(),
            "signer": AUTHORITY_REF,
        },
        "fetchedAt": verified_at - 1_000,
        "verifiedAt": verified_at,
    }
    if valid_until is not None:
        unsigned["validUntil"] = valid_until
    return sign_component(unsigned, AUTHORITY, AUTHORITY_REF, VERIFY_RESULT_DOMAIN)


def result_ref(result: dict, label: str) -> dict:
    return {
        "anchor": {
            "kind": "storage-program",
            "locator": f"demos:presence-vector:{label}",
        },
        "contentHash": hash_hex(result),
        "recipeVersion": result["recipeVersion"],
    }


def requirement(
    required: list[dict],
    *,
    one_of: list[list[dict]] | None = None,
    selector: str | None = None,
) -> dict:
    value = {"requirementVersion": "1", "required": copy.deepcopy(required)}
    if one_of is not None:
        value["oneOf"] = copy.deepcopy(one_of)
    if selector is not None:
        value["primaryClaimSelector"] = selector
    return value


def presence(scheme: str, **fields: object) -> dict:
    value = {"scheme": scheme, "verificationRequired": False}
    value.update(copy.deepcopy(fields))
    return value


def verified(scheme: str, **fields: object) -> dict:
    value = {"scheme": scheme, "verificationRequired": True}
    value.update(copy.deepcopy(fields))
    return value


def signed_composite(
    bundle: dict,
    req: dict,
    refs: list[dict],
    overall: str,
    *,
    job_id: str,
) -> dict:
    unsigned_bundle = {key: value for key, value in bundle.items() if key != "presentation"}
    unsigned = {
        "recordVersion": "1",
        "jobId": job_id,
        "evaluatedParty": bundle["presentedBy"],
        "bundleHash": hash_hex(unsigned_bundle),
        "requirementHash": hash_hex(req),
        "freshness": [],
        "supplementary": [],
        "dealSpecific": copy.deepcopy(refs),
        "overallDecision": overall,
        "generatedAt": NOW,
    }
    return sign_component(unsigned, VERIFIER, VERIFIER_REF, COMPOSITE_DOMAIN)


def case(
    name: str,
    expected: str,
    bundle: dict,
    req: dict,
    *,
    refs: list[dict] | None = None,
    resolved: list[tuple[dict, dict]] | None = None,
    overall: str | None = None,
    note: str,
) -> dict:
    refs = refs or []
    record = signed_composite(
        bundle,
        req,
        refs,
        overall or (expected if expected in {"pass", "fail", "indeterminate", "error"} else "error"),
        job_id=f"pcr-{name}",
    )
    return {
        "name": name,
        "expected": expected,
        "note": note,
        "evaluatedAt": NOW,
        "registryAvailable": True,
        "registryAuthenticated": True,
        "bundleAvailable": True,
        "bundle": copy.deepcopy(bundle),
        "requirement": copy.deepcopy(req),
        "compositeRecord": record,
        "resolvedResults": [
            {"ref": copy.deepcopy(ref), "artifact": copy.deepcopy(artifact)}
            for ref, artifact in (resolved or [])
        ],
    }


def resign_bundle(bundle: dict, key: Ed25519PrivateKey = PRESENTER,
                  signer_ref: str = PRESENTER_REF) -> None:
    unsigned = {field: value for field, value in bundle.items() if field != "presentation"}
    bundle["presentation"] = {
        "kind": "per-claim",
        "signatures": [{
            "ref": signer_ref,
            "signature": b64url(key.sign((BUNDLE_DOMAIN + hash_hex(unsigned)).encode("ascii"))),
        }],
    }


def resign_record(record: dict) -> None:
    unsigned = {field: value for field, value in record.items() if field != "signature"}
    record["signature"] = sign_component(
        unsigned, VERIFIER, VERIFIER_REF, COMPOSITE_DOMAIN
    )["signature"]


def build_vectors() -> list[dict]:
    vectors: list[dict] = []
    base_key = claim(PRESENTER_REF, issuedAt=NOW - 500_000)

    vectors.append(case(
        "required-presence-key-with-issued-at",
        "pass",
        signed_bundle([base_key]),
        requirement([presence("key")]),
        note="PCR-2 accepts a present controlled key without verifiedBy; issuedAt is informational",
    ))
    vectors.append(case(
        "required-presence-key-without-issued-at",
        "pass",
        signed_bundle([claim(PRESENTER_REF)]),
        requirement([presence("key")]),
        note="PCR-2 does not require issuedAt in presence mode",
    ))
    vectors.append(case(
        "required-presence-missing",
        "fail",
        signed_bundle([base_key]),
        requirement([presence("lei")]),
        note="A missing presence-only claim is a conclusive non-match",
    ))
    vectors.append(case(
        "required-presence-expired",
        "fail",
        signed_bundle([base_key, claim(LEI_REF, expiresAt=NOW - 1)]),
        requirement([presence("lei")]),
        note="PCR-2 retains the presenter expiry boundary",
    ))
    vectors.append(case(
        "future-issued-at-is-informational",
        "pass",
        signed_bundle([claim(PRESENTER_REF, issuedAt=NOW + 86_400_000)]),
        requirement([presence("key")]),
        note="Presence does not reinterpret issuedAt as authority evidence or a freshness gate",
    ))

    failing_vr = verify_result(PRESENTER_REF, "fail")
    failing_ref = result_ref(failing_vr, "optional-fail")
    vectors.append(case(
        "optional-failing-verification-does-not-defeat-presence",
        "pass",
        signed_bundle([claim(PRESENTER_REF, verifiedBy=failing_ref)]),
        requirement([presence("key")]),
        resolved=[(failing_ref, failing_vr)],
        note="PCR-3 does not resolve or promote an optional failing result for presence",
    ))

    stale_vr = verify_result(
        PRESENTER_REF, "pass", verified_at=NOW - 7_200_000,
        valid_until=NOW - 3_600_000,
    )
    stale_ref = result_ref(stale_vr, "optional-stale")
    vectors.append(case(
        "optional-stale-verification-does-not-defeat-presence",
        "pass",
        signed_bundle([claim(PRESENTER_REF, verifiedBy=stale_ref)]),
        requirement([presence("key")]),
        resolved=[(stale_ref, stale_vr)],
        note="PCR-3 skips verification freshness for a presence-only decision",
    ))

    unavailable_ref = {
        "anchor": {"kind": "https", "locator": "https://unavailable.example/result"},
        "contentHash": "ab" * 32,
        "recipeVersion": 1,
    }
    vectors.append(case(
        "optional-unavailable-verification-does-not-defeat-presence",
        "pass",
        signed_bundle([claim(PRESENTER_REF, verifiedBy=unavailable_ref)]),
        requirement([presence("key")]),
        note="A well-shaped but unavailable optional result is not fetched for presence",
    ))

    malformed_bundle = signed_bundle([claim(PRESENTER_REF)])
    malformed_bundle["claims"][0]["verifiedBy"] = {
        "anchor": "not-an-anchor", "contentHash": "cd" * 32, "recipeVersion": 1,
    }
    resign_bundle(malformed_bundle)
    vectors.append(case(
        "malformed-optional-verification-reference",
        "error",
        malformed_bundle,
        requirement([presence("key")]),
        note="PCR-3 preserves the VerifyResultRef wire-shape boundary",
    ))
    vectors.append(case(
        "presence-max-age-is-invalid",
        "error",
        signed_bundle([base_key]),
        requirement([presence("key", maxAge=60)]),
        overall="pass",
        note="PCR-1 rejects maxAge where no authority window exists",
    ))
    vectors.append(case(
        "presence-recipe-version-is-invalid",
        "error",
        signed_bundle([base_key]),
        requirement([presence("key", recipeVersion=1)]),
        overall="pass",
        note="PCR-1 rejects recipeVersion rather than manufacturing a result",
    ))
    vectors.append(case(
        "verification-required-must-be-boolean",
        "error",
        signed_bundle([base_key]),
        requirement([{"scheme": "key", "verificationRequired": "false"}]),
        overall="pass",
        note="PCR-1 rejects a string lookalike rather than selecting a truthy mode",
    ))
    vectors.append(case(
        "empty-member-collections-are-vacuously-satisfied",
        "pass",
        signed_bundle([base_key]),
        requirement([], one_of=[]),
        note="Empty required and oneOf collections impose no member constraint",
    ))
    vectors.append(case(
        "empty-oneof-group-is-invalid",
        "error",
        signed_bundle([base_key]),
        requirement([], one_of=[[]]),
        overall="fail",
        note="An empty inner oneOf group is a malformed requirement, not silent pass or fail",
    ))
    vectors.append(case(
        "oneof-passing-member-cannot-mask-unknown-scheme",
        "error",
        signed_bundle([base_key]),
        requirement([], one_of=[[presence("unknown"), presence("key")]]),
        overall="pass",
        note="DACS-1 requirement preflight rejects every unknown scheme before oneOf any-pass",
    ))
    vectors.append(case(
        "presence-parameters-must-be-an-object",
        "error",
        signed_bundle([base_key]),
        requirement([presence("key", parameters=[])]),
        overall="fail",
        note="Malformed parameters are a requirement error rather than an evaluator exception",
    ))
    vectors.append(case(
        "presence-parameters-match",
        "pass",
        signed_bundle([base_key, claim(LEI_REF, metadata={"jurisdiction": "GB"})]),
        requirement([presence("lei", parameters={"jurisdiction": "GB"})]),
        note="PCR-2 applies authenticated scheme parameters in presence mode",
    ))
    vectors.append(case(
        "presence-parameters-mismatch",
        "fail",
        signed_bundle([base_key, claim(LEI_REF, metadata={"jurisdiction": "US"})]),
        requirement([presence("lei", parameters={"jurisdiction": "GB"})]),
        note="Parameter mismatch is a non-match, not a verification attempt",
    ))
    vectors.append(case(
        "oneof-presence-alternative-passes",
        "pass",
        signed_bundle([base_key]),
        requirement([], one_of=[[presence("key"), presence("lei")]]),
        note="A presence-only member can satisfy its oneOf group",
    ))
    vectors.append(case(
        "oneof-presence-group-unsatisfied",
        "fail",
        signed_bundle([base_key]),
        requirement([], one_of=[[presence("lei"), presence("did")]]),
        note="A oneOf group with no present alternative fails",
    ))

    did_vr = verify_result(DID_REF, "pass")
    did_result_ref = result_ref(did_vr, "did-pass")
    mixed_bundle = signed_bundle([
        base_key,
        claim(DID_REF, verifiedBy=did_result_ref),
    ])
    mixed_req = requirement([presence("key"), verified("did")])
    vectors.append(case(
        "mixed-required-presence-and-verified-pass",
        "pass",
        mixed_bundle,
        mixed_req,
        refs=[did_result_ref],
        resolved=[(did_result_ref, did_vr)],
        note="PCR-6 composes direct bundle presence with ordinary VerifyResult evidence",
    ))

    did_fail_vr = verify_result(DID_REF, "fail")
    did_fail_ref = result_ref(did_fail_vr, "did-fail")
    vectors.append(case(
        "mixed-required-verified-failure-dominates",
        "fail",
        signed_bundle([base_key, claim(DID_REF, verifiedBy=did_fail_ref)]),
        mixed_req,
        refs=[did_fail_ref],
        resolved=[(did_fail_ref, did_fail_vr)],
        note="A presence pass cannot rescue a failing verification-required member",
    ))
    vectors.append(case(
        "mixed-oneof-presence-beats-verified-failure",
        "pass",
        signed_bundle([base_key, claim(DID_REF, verifiedBy=did_fail_ref)]),
        requirement([], one_of=[[presence("key"), verified("did")]]),
        refs=[did_fail_ref],
        resolved=[(did_fail_ref, did_fail_vr)],
        note="OR semantics permit the presence alternative while retaining the failed result",
    ))
    vectors.append(case(
        "verified-member-cannot-use-bare-presence",
        "fail",
        signed_bundle([base_key, claim(DID_REF)]),
        requirement([verified("did")]),
        note="PCR-4 requires a passing fresh result; a present claim is insufficient",
    ))

    synthetic_vr = verify_result(PRESENTER_REF, "pass")
    synthetic_ref = result_ref(synthetic_vr, "synthetic-presence")
    vectors.append(case(
        "synthetic-presence-verify-result-rejected",
        "error",
        signed_bundle([claim(PRESENTER_REF, verifiedBy=synthetic_ref)]),
        requirement([presence("key")]),
        refs=[synthetic_ref],
        resolved=[(synthetic_ref, synthetic_vr)],
        overall="pass",
        note="PCR-6 rejects a CVR result reference attributable only to presence",
    ))

    hash_mismatch = case(
        "bundle-hash-substitution-rejected",
        "error",
        signed_bundle([base_key]),
        requirement([presence("key")]),
        overall="pass",
        note="Strict replay binds presence to the exact bundleHash",
    )
    hash_mismatch["compositeRecord"]["bundleHash"] = "00" * 32
    resign_record(hash_mismatch["compositeRecord"])
    vectors.append(hash_mismatch)

    requirement_mismatch = case(
        "requirement-hash-substitution-rejected",
        "error",
        signed_bundle([base_key]),
        requirement([presence("key")]),
        overall="pass",
        note="Strict replay binds the exact requirement including its evaluation mode",
    )
    requirement_mismatch["compositeRecord"]["requirementHash"] = "11" * 32
    resign_record(requirement_mismatch["compositeRecord"])
    vectors.append(requirement_mismatch)

    bad_bundle_sig = case(
        "invalid-bundle-presentation-rejected",
        "error",
        signed_bundle([base_key]),
        requirement([presence("key")]),
        overall="pass",
        note="Presence is authenticated by the bundle presentation",
    )
    signature = bad_bundle_sig["bundle"]["presentation"]["signatures"][0]["signature"]
    bad_bundle_sig["bundle"]["presentation"]["signatures"][0]["signature"] = (
        ("A" if signature[0] != "A" else "B") + signature[1:]
    )
    vectors.append(bad_bundle_sig)

    bad_record_sig = case(
        "invalid-composite-signature-rejected",
        "error",
        signed_bundle([base_key]),
        requirement([presence("key")]),
        overall="pass",
        note="PCR-6 does not weaken the signed composite-record boundary",
    )
    signature = bad_record_sig["compositeRecord"]["signature"]["value"]
    bad_record_sig["compositeRecord"]["signature"]["value"] = (
        ("A" if signature[0] != "A" else "B") + signature[1:]
    )
    vectors.append(bad_record_sig)

    unavailable_bundle = case(
        "exact-bundle-unavailable-is-indeterminate",
        "indeterminate",
        signed_bundle([base_key]),
        requirement([presence("key")]),
        overall="pass",
        note="A standalone CVR cannot prove presence without its exact bundle companion",
    )
    unavailable_bundle["bundleAvailable"] = False
    unavailable_bundle["bundle"] = None
    vectors.append(unavailable_bundle)

    unavailable_bundle_bad_registry = case(
        "invalid-registry-precedes-unavailable-bundle",
        "error",
        signed_bundle([base_key]),
        requirement([presence("key")]),
        overall="pass",
        note="CRQ-1 authenticates the session-pinned registry before missing bundle availability can yield indeterminate",
    )
    unavailable_bundle_bad_registry["registryAvailable"] = False
    unavailable_bundle_bad_registry["registryAuthenticated"] = False
    unavailable_bundle_bad_registry["bundleAvailable"] = False
    unavailable_bundle_bad_registry["bundle"] = None
    vectors.append(unavailable_bundle_bad_registry)

    unavailable_bad_record = case(
        "invalid-composite-still-rejects-without-bundle",
        "error",
        signed_bundle([base_key]),
        requirement([presence("key")]),
        overall="pass",
        note="Composite authentication precedes the missing-bundle indeterminate branch",
    )
    signature = unavailable_bad_record["compositeRecord"]["signature"]["value"]
    unavailable_bad_record["compositeRecord"]["signature"]["value"] = (
        ("A" if signature[0] != "A" else "B") + signature[1:]
    )
    unavailable_bad_record["bundleAvailable"] = False
    unavailable_bad_record["bundle"] = None
    vectors.append(unavailable_bad_record)

    vectors.append(case(
        "presence-key-selector-has-independent-control",
        "pass",
        signed_bundle([base_key]),
        requirement([presence("key")], selector="key"),
        note="PCR-5 permits the exact key selector because its bundle signature proves control",
    ))
    vectors.append(case(
        "presence-lei-selector-does-not-establish-control",
        "fail",
        signed_bundle([base_key, claim(LEI_REF)], presented_by=LEI_REF),
        requirement([presence("lei")], selector="lei"),
        overall="fail",
        note="Existence-only LEI presence cannot become controlled presentedBy or reputation identity",
    ))
    vectors.append(case(
        "unauthorized-selector-dominates-unavailable-member",
        "fail",
        signed_bundle(
            [base_key, claim(LEI_REF), claim(DID_REF, verifiedBy=unavailable_ref)],
            presented_by=LEI_REF,
        ),
        requirement(
            [presence("lei"), verified("did")], selector="lei"
        ),
        refs=[unavailable_ref],
        overall="fail",
        note="Independent selector failure has global fail-first precedence over an indeterminate verified member",
    ))
    vectors.append(case(
        "stale-optional-key-result-does-not-remove-key-control",
        "pass",
        signed_bundle([claim(PRESENTER_REF, verifiedBy=stale_ref)]),
        requirement([presence("key")], selector="key"),
        resolved=[(stale_ref, stale_vr)],
        note="The key presentation proves control while the stale result supplies no tier elevation",
    ))

    second_vr = verify_result(SECOND_REF, "pass")
    second_result_ref = result_ref(second_vr, "second-key-pass")
    laundering_bundle = signed_bundle([
        base_key,
        claim(SECOND_REF, verifiedBy=second_result_ref),
    ])
    vectors.append(case(
        "different-verified-same-scheme-cannot-launder-selector",
        "fail",
        laundering_bundle,
        requirement([presence("key"), verified("key")], selector="key"),
        refs=[second_result_ref],
        resolved=[(second_result_ref, second_vr)],
        overall="fail",
        note="MA-3/PCR-5 require the exact selected claim when the same scheme is mandatory-verified",
    ))

    decision_mismatch = case(
        "signed-overall-decision-mismatch-rejected",
        "error",
        signed_bundle([base_key]),
        requirement([presence("lei")]),
        overall="pass",
        note="A strict consumer recomputes aggregation instead of trusting signed overallDecision",
    )
    vectors.append(decision_mismatch)

    return vectors


def document() -> dict:
    vectors = build_vectors()
    return {
        "set": "presence-only-claim-requirement-v0.7",
        "spec": "DACS-1 §6.3.3 PCR-1..PCR-6; DACS-2 §7.7.1",
        "tier": "candidate",
        "description": (
            "Signed mixed-mode ClaimRequirement vectors for presence-only matching, "
            "CVR replay, and the control/tier boundary."
        ),
        "provenance": {
            "issue": "DACS-Agent-commerce/DACS-Standard#334",
            "generator": "scripts/generate_presence_only_claim_vectors.py",
        },
        "publicKeys": {
            "presenter": public_hex(PRESENTER),
            "secondPresenter": public_hex(SECOND_PRESENTER),
            "authority": public_hex(AUTHORITY),
            "verifier": public_hex(VERIFIER),
        },
        "count": len(vectors),
        "hash": hashlib.sha256(canonical_bytes(vectors)).hexdigest(),
        "vectors": vectors,
    }


def render() -> str:
    return json.dumps(document(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    generated = render()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != generated:
            print(
                "ERROR: presence-only vectors are stale; run "
                "python3 scripts/generate_presence_only_claim_vectors.py --write"
            )
            return 1
        print("presence-only claim vectors OK (deterministic generator output)")
        return 0
    OUTPUT.write_text(generated, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({document()['count']} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
