#!/usr/bin/env python3
"""Generate deterministic DACS-1/DACS-2 PCR-1..PCR-6 vectors."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_conformance_vectors as vcv  # noqa: E402

OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "presence-only-claim-requirement-v0.7.json"
)
NOW = 1_900_000_000_000
BUNDLE_DOMAIN = "dacs-bundle-presentation:v1:"
VERIFY_RESULT_DOMAIN = "dacs-verifyresult:v1:"
COMPOSITE_DOMAIN = "dacs-composite:v1:"


def canonical_bytes(value: object) -> bytes:
    return vcv.canonical_json(value)


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
UNAUTHORIZED_AUTHORITY = private_key("dacs-334-unauthorized-authority")
VERIFIER = private_key("dacs-334-verifier")
ORCHESTRATOR = private_key("dacs-362-orchestrator")
PRESENTER_REF = f"key:{public_hex(PRESENTER)}"
SECOND_REF = f"key:{public_hex(SECOND_PRESENTER)}"
AUTHORITY_REF = f"key:{public_hex(AUTHORITY)}"
UNAUTHORIZED_AUTHORITY_REF = f"key:{public_hex(UNAUTHORIZED_AUTHORITY)}"
VERIFIER_REF = f"key:{public_hex(VERIFIER)}"
ORCHESTRATOR_REF = f"key:{public_hex(ORCHESTRATOR)}"
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
    valid_until: object = NOW + 3_600_000,
    recipe_version: int = 1,
    method: str = "self-signed",
    data: dict | None = None,
    signer_key: Ed25519PrivateKey = AUTHORITY,
    signer_ref: str = AUTHORITY_REF,
) -> dict:
    scheme, identifier = ref.split(":", 1)
    unsigned = {
        "resultVersion": "1",
        "scheme": scheme,
        "identifier": identifier,
        "recipeVersion": recipe_version,
        "method": method,
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
            "signer": signer_ref,
        },
        "fetchedAt": verified_at - 1_000,
        "verifiedAt": verified_at,
    }
    if valid_until is not None:
        unsigned["validUntil"] = valid_until
    if data is not None:
        unsigned["data"] = copy.deepcopy(data)
    return sign_component(unsigned, signer_key, signer_ref, VERIFY_RESULT_DOMAIN)


def result_ref(result: dict, label: str) -> dict:
    return {
        "anchor": {
            "kind": "storage-program",
            "locator": f"demos:presence-vector:{label}",
        },
        "contentHash": vcv.artifact_hash_hex("VerifyResult", result),
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
    freshness: list[dict],
    refs: list[dict],
    overall: str,
    *,
    job_id: str,
    generated_at: int = NOW,
) -> dict:
    unsigned_bundle = {key: value for key, value in bundle.items() if key != "presentation"}
    unsigned = {
        "recordVersion": "1",
        "jobId": job_id,
        "evaluatedParty": bundle["presentedBy"],
        "bundleHash": hash_hex(unsigned_bundle),
        "requirementHash": hash_hex(req),
        "freshness": copy.deepcopy(freshness),
        "supplementary": [],
        "dealSpecific": copy.deepcopy(refs),
        "overallDecision": overall,
        "generatedAt": generated_at,
    }
    return sign_component(unsigned, VERIFIER, VERIFIER_REF, COMPOSITE_DOMAIN)


def case(
    name: str,
    expected: str,
    bundle: dict,
    req: dict,
    *,
    freshness: list[dict] | None = None,
    refs: list[dict] | None = None,
    resolved: list[tuple[dict, dict]] | None = None,
    overall: str | None = None,
    generated_at: int = NOW,
    note: str,
) -> dict:
    bundle = copy.deepcopy(bundle)
    nonce = hashlib.sha256(f"dacs-362:{name}:nonce".encode("utf-8")).hexdigest()[:32]
    bundle["sessionNonce"] = nonce
    resign_bundle(bundle)
    freshness = freshness or []
    refs = refs or []
    job_id = deterministic_ulid(name)
    record = signed_composite(
        bundle,
        req,
        freshness,
        refs,
        overall or (expected if expected in {"pass", "fail", "indeterminate", "error"} else "error"),
        job_id=job_id,
        generated_at=generated_at,
    )
    return {
        "name": name,
        "expected": expected,
        "note": note,
        "evaluatedAt": NOW,
        "authority": {
            "kind": "vet-invocation",
            "invocation": name,
            "nonce": nonce,
        },
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


ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def deterministic_ulid(label: str) -> str:
    value = int.from_bytes(
        hashlib.sha256(f"dacs-362:{label}:job".encode("utf-8")).digest()[:16],
        "big",
    )
    chars = []
    for _ in range(26):
        chars.append(ULID_ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(chars))


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

    key_vr = verify_result(PRESENTER_REF, "pass")
    key_result_ref = result_ref(key_vr, "key-pass-freshness")
    vectors.append(case(
        "complete-ordered-freshness-then-deal-specific-results",
        "pass",
        signed_bundle([
            claim(PRESENTER_REF, verifiedBy=key_result_ref),
            claim(DID_REF, verifiedBy=did_result_ref),
        ]),
        requirement([verified("key"), verified("did")]),
        freshness=[key_result_ref],
        refs=[did_result_ref],
        resolved=[(key_result_ref, key_vr), (did_result_ref, did_vr)],
        note=(
            "CRQ-1 binds the complete ordered freshness plus dealSpecific "
            "reference projection before artifact authentication"
        ),
    ))

    parameter_vr = verify_result(
        DID_REF,
        "pass",
        data={"jurisdiction": "GB", "status": "active", "extra": "retained"},
    )
    parameter_ref = result_ref(parameter_vr, "did-authenticated-parameters")
    vectors.append(case(
        "verified-parameters-use-authenticated-result-data",
        "pass",
        signed_bundle([
            base_key,
            claim(
                DID_REF,
                metadata={"jurisdiction": "US"},
                verifiedBy=parameter_ref,
            ),
        ]),
        requirement([
            verified("did", parameters={"jurisdiction": "GB"})
        ]),
        refs=[parameter_ref],
        resolved=[(parameter_ref, parameter_vr)],
        note=(
            "Verified predicates use authenticated VerifyResult.data and allow "
            "additional data instead of trusting same-scheme bundle metadata"
        ),
    ))
    vectors.append(case(
        "verified-parameters-ignore-matching-bundle-metadata",
        "fail",
        signed_bundle([
            base_key,
            claim(
                DID_REF,
                metadata={"jurisdiction": "US"},
                verifiedBy=parameter_ref,
            ),
        ]),
        requirement([
            verified("did", parameters={"jurisdiction": "US"})
        ]),
        refs=[parameter_ref],
        resolved=[(parameter_ref, parameter_vr)],
        note=(
            "A same-scheme claim's metadata cannot satisfy a verified predicate "
            "that the authenticated result data does not satisfy"
        ),
    ))
    vectors.append(case(
        "one-authenticated-result-may-satisfy-multiple-predicates",
        "pass",
        signed_bundle([
            base_key, claim(DID_REF, verifiedBy=parameter_ref),
        ]),
        requirement([
            verified("did", parameters={"jurisdiction": "GB"}),
            verified("did", parameters={"status": "active"}),
        ]),
        refs=[parameter_ref],
        resolved=[(parameter_ref, parameter_vr)],
        note=(
            "One authenticated result can qualify multiple requirements when "
            "its data genuinely satisfies each predicate"
        ),
    ))

    malformed_time_vr = verify_result(DID_REF, "pass", valid_until=[])
    malformed_time_ref = result_ref(malformed_time_vr, "invalid-valid-until")
    vectors.append(case(
        "verify-result-valid-until-container-is-error",
        "error",
        signed_bundle([
            base_key, claim(DID_REF, verifiedBy=malformed_time_ref),
        ]),
        requirement([verified("did")]),
        refs=[malformed_time_ref],
        resolved=[(malformed_time_ref, malformed_time_vr)],
        overall="pass",
        note="A non-integer validUntil is rejected without a comparison exception",
    ))

    historical_vr = verify_result(
        DID_REF,
        "pass",
        verified_at=NOW - 20_000,
        valid_until=NOW - 500,
        data={"status": "active"},
    )
    historical_ref = result_ref(historical_vr, "historical-pass")
    historical = case(
        "signed-generated-at-reconstructs-historical-decision",
        "pass",
        signed_bundle([
            base_key, claim(DID_REF, verifiedBy=historical_ref),
        ]),
        requirement([
            verified("did", parameters={"status": "active"})
        ]),
        refs=[historical_ref],
        resolved=[(historical_ref, historical_vr)],
        generated_at=NOW - 1_000,
        note=(
            "The signed generatedAt reconstructs the original pass even though "
            "trusted current time no longer permits VP-C1 reuse"
        ),
    )
    historical["evaluatedAt"] = 0
    vectors.append(historical)

    reusable_vr = verify_result(
        DID_REF,
        "pass",
        data={"status": "active", "jurisdiction": "GB"},
    )
    reusable_ref = result_ref(reusable_vr, "cross-session-reusable")
    for suffix in ("first", "second"):
        vectors.append(case(
            f"cross-session-pass-reuse-{suffix}",
            "pass",
            signed_bundle([
                base_key, claim(DID_REF, verifiedBy=reusable_ref),
            ]),
            requirement([
                verified("did", parameters={"status": "active"})
            ]),
            refs=[reusable_ref],
            resolved=[(reusable_ref, reusable_vr)],
            note=(
                "VP-C1..VP-C3 reuse keeps the VerifyResult session-agnostic while "
                "the outer aggregate carries distinct job and nonce admission"
            ),
        ))

    unauthorized_did_vr = verify_result(
        DID_REF,
        "pass",
        signer_key=UNAUTHORIZED_AUTHORITY,
        signer_ref=UNAUTHORIZED_AUTHORITY_REF,
    )
    unauthorized_did_ref = result_ref(
        unauthorized_did_vr, "unauthorized-result-signer"
    )
    vectors.append(case(
        "authorized-result-signer-substitution-rejected",
        "error",
        signed_bundle([
            base_key,
            claim(DID_REF, verifiedBy=unauthorized_did_ref),
        ]),
        mixed_req,
        refs=[unauthorized_did_ref],
        resolved=[(unauthorized_did_ref, unauthorized_did_vr)],
        overall="pass",
        note=(
            "CRQ-1 rejects a valid alternate-key signature because its signer is not "
            "the independently authenticated authority for the recipe family"
        ),
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
        resolved=[(unavailable_ref, None)],
        overall="fail",
        note="Independent selector failure has global fail-first precedence over an indeterminate verified member",
    ))
    vectors.append(case(
        "stale-optional-key-result-does-not-remove-key-control",
        "pass",
        signed_bundle([claim(PRESENTER_REF, verifiedBy=stale_ref)]),
        requirement([presence("key")], selector="key"),
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


def trusted_context(vectors: list[dict]) -> dict:
    invocations = {}
    issuances = []
    for index, vector in enumerate(vectors):
        name = vector["name"]
        record = vector["compositeRecord"]
        authority = vector["authority"]
        same_actor_roles = index == 0
        challenge_id = f"pcr-{name}"
        invocations[name] = {
            "jobId": record["jobId"],
            # Fixture setup models the orchestrator's retained phase input.
            # The consumer never initializes this authority from an artifact.
            "sessionContext": {"jobId": record["jobId"], "recipeRegistryVersion": 1},
            "recipeRegistryVersion": 1,
            "requirementHash": hash_hex(vector["requirement"]),
            "bundleInputHash": hash_hex(vector["bundle"]),
            "sessionState": "vet-pending",
            "phaseKind": "vet-credentials",
            "phaseIndex": 1,
            "attempt": 1,
            "actor": "buyer",
            "evaluatedParty": record["evaluatedParty"],
            "expectedVerifierRole": (
                "orchestrator" if same_actor_roles else "counterparty"
            ),
            "expectedVerifier": VERIFIER_REF,
            "phaseOrchestrator": (
                VERIFIER_REF if same_actor_roles else ORCHESTRATOR_REF
            ),
            "challengeId": challenge_id,
            "trustedNow": NOW,
            "registryAvailable": vector["registryAvailable"],
            "registryAuthenticated": vector["registryAuthenticated"],
            "bundleAvailable": vector["bundleAvailable"],
        }
        issuances.append({
            "challengeId": challenge_id,
            "nonce": authority["nonce"],
            "jobId": record["jobId"],
            "actor": "buyer",
            "evaluatedParty": record["evaluatedParty"],
            "phaseIndex": 1,
            "attempt": 1,
            "expectedVerifier": VERIFIER_REF,
            "issuedBy": VERIFIER_REF,
            "issuedAt": NOW - 60_000,
            "expiresAt": NOW + 60_000,
        })
    return {
        "compositeSigner": VERIFIER_REF,
        "recipeRegistryVersion": 1,
        "authenticatedSessionStarts": {
            record["jobId"]: {"jobId": record["jobId"], "recipeRegistryVersion": 1}
            for record in (vector["compositeRecord"] for vector in vectors)
        },
        "verifyResultAuthorities": [
            {
                "scheme": "key",
                "method": "self-signed",
                "recipeVersion": 1,
                "signer": AUTHORITY_REF,
                "defaultMaxAgeSec": 3_600,
                "availability": "live",
            },
            {
                "scheme": "did",
                "method": "self-signed",
                "recipeVersion": 1,
                "signer": AUTHORITY_REF,
                "defaultMaxAgeSec": 3_600,
                "availability": "live",
            },
        ],
        "vetInvocations": invocations,
        "nonceIssuances": issuances,
    }


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
            "unauthorizedAuthority": public_hex(UNAUTHORIZED_AUTHORITY),
            "verifier": public_hex(VERIFIER),
            "orchestrator": public_hex(ORCHESTRATOR),
        },
        "trustedContext": trusted_context(vectors),
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
