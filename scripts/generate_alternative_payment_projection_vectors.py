#!/usr/bin/env python3
"""Generate deterministic APR-1..APR-8 alternative-payment vectors."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize as jcs_canonicalize


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/vectors/security/alternative-payment-projection-v0.1.json"
JOB_DEM = "01M0Q4K8X5D9YJKC3VT7H2N6PA"
JOB_X402 = "01M0Q4K8X5D9YJKC3VT7H2N6PB"
SELLER = "did:demos:agent:" + "22" * 32
BUYER = "did:demos:agent:" + "11" * 32
STEWARD = "did:demos:agent:" + "44" * 32
SEEDS = {
    "seller": hashlib.sha256(b"DACS #340 seller").digest(),
    "buyer": hashlib.sha256(b"DACS #340 buyer").digest(),
    "steward": hashlib.sha256(b"DACS #340 steward").digest(),
}
CLAIMS = {"seller": SELLER, "buyer": BUYER, "steward": STEWARD}
DEM_REF = {"railId": "demos-native:DEM", "railVersion": 1}
X402_REF = {
    "railId": "x402:default",
    "railVersion": 1,
    "parameters": {"resource": "https://seller.example/pay/340"},
}
CASE_FIELDS = {
    "name", "expected", "expectedReason", "rule", "operation", "note", "base",
}


def key(role: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(SEEDS[role])


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def public_key(role: str) -> str:
    return b64u(key(role).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))


def digest(value: object) -> str:
    return hashlib.sha256(jcs_canonicalize(value).encode("utf-8")).hexdigest()


def signature(role: str, domain: str, body: object) -> str:
    return b64u(key(role).sign((domain + digest(body)).encode("ascii")))


def unsigned(value: dict, field: str) -> dict:
    return {name: item for name, item in value.items() if name != field}


def rail_definition(ref: dict, handler: str) -> dict:
    if handler == "pay-dem":
        rail_type = "demos-native"
        asset = {"kind": "native-dem", "symbol": "DEM", "decimals": 9}
        network = {"kind": "demos"}
        parameters = {"transfer": "native"}
    else:
        rail_type = "x402"
        asset = {
            "kind": "erc20",
            "chainId": 8453,
            "contract": "0x" + "33" * 20,
            "symbol": "USDC",
            "decimals": 6,
        }
        network = {
            "kind": "x402-resource",
            "resourceBaseUrl": ref.get("parameters", {}).get("resource", "https://seller.example/pay/340"),
        }
        parameters = {"authorization": "eip-3009"}
    return {
        "railVersion": ref["railVersion"],
        "railId": ref["railId"],
        "railType": rail_type,
        "asset": asset,
        "network": network,
        "phaseHandler": handler,
        "parameters": parameters,
        "availability": "live",
        "governance": {
            "proposedBy": STEWARD,
            "acceptedAt": 1787616000000,
            "anchoring": "single-signer",
        },
    }


def effective_pipeline(listing: dict, selected_ref: dict, handler: str) -> list[dict]:
    projected = []
    for phase in listing["pipeline"]:
        if phase.get("kind") == "pay-alternative":
            projected.append({
                "kind": handler,
                "parameters": {"rail": selected_ref["railId"]},
            })
        else:
            projected.append(copy.deepcopy(phase))
    return projected


def make_base(selected: str = "dem", *, ordinary_repeated: bool = False) -> dict:
    selected_ref = copy.deepcopy(DEM_REF if selected == "dem" else X402_REF)
    handler = "pay-dem" if selected == "dem" else "pay-x402"
    job_id = JOB_DEM if selected == "dem" else JOB_X402
    if ordinary_repeated:
        pipeline = [
            {"kind": "negotiate-fixed-price"},
            {"kind": "commit-payee-bound-agreement"},
            {"kind": "pay-dem", "parameters": {"rail": DEM_REF["railId"]}},
            {"kind": "deliver-storage-program"},
            {"kind": "pay-dem", "parameters": {"rail": DEM_REF["railId"]}},
        ]
        accepted = [copy.deepcopy(DEM_REF)]
    else:
        pipeline = [
            {"kind": "negotiate-fixed-price"},
            {"kind": "commit-payee-bound-agreement"},
            {
                "kind": "pay-alternative",
                "parameters": {
                    "alternatives": [copy.deepcopy(DEM_REF), copy.deepcopy(X402_REF)]
                },
            },
            {"kind": "deliver-storage-program"},
        ]
        accepted = [copy.deepcopy(DEM_REF), copy.deepcopy(X402_REF)]
    listing = {
        "dacsVersion": "1",
        "listingVersion": 1,
        "listingId": "apr-340",
        "pipeline": pipeline,
        "acceptedRails": accepted,
    }
    definitions = {
        digest(DEM_REF): rail_definition(DEM_REF, "pay-dem"),
        digest(X402_REF): rail_definition(X402_REF, "pay-x402"),
    }
    resolutions = [
        {
            "snapshotId": "registry-snapshot-340",
            "ref": copy.deepcopy(ref),
            "status": "verified",
            "definition": copy.deepcopy(definitions[digest(ref)]),
        }
        for ref in accepted
    ]
    payout_indexes = [
        index for index, phase in enumerate(
            effective_pipeline(listing, selected_ref, handler)
        ) if phase["kind"].startswith("pay-")
    ]
    agreement = {
        "payeeBoundAgreementVersion": "1",
        "jobId": job_id,
        "listingRef": {
            "listingId": listing["listingId"],
            "version": listing["listingVersion"],
            "contentHash": "",
        },
        "parties": [
            {"role": "buyer", "primaryClaim": BUYER, "bundleHash": "aa" * 32},
            {"role": "seller", "primaryClaim": SELLER, "bundleHash": "bb" * 32},
        ],
        "terms": {
            "price": {"amount": "1", "currency": "DEM" if selected == "dem" else "USDC"},
            "rail": selected_ref,
            "payoutBindings": [
                {
                    "railId": selected_ref["railId"],
                    "phaseIndex": index,
                    "payeeAddress": SELLER,
                }
                for index in payout_indexes
            ],
        },
        "derivedFromPattern": "fixed-price",
        "generatedAt": 1787616001000,
    }
    projected = effective_pipeline(listing, selected_ref, handler)
    value = {
        "listing": listing,
        "agreement": agreement,
        "registry": {
            "authorityAuthenticated": True,
            "stewardClaim": STEWARD,
            "snapshotId": "registry-snapshot-340",
            "resolutions": resolutions,
        },
        "runtime": {
            "listingPublisherClaim": SELLER,
            "readerSupportsPayAlternative": True,
            "supportedHandlers": ["pay-dem", "pay-x402"],
            "projectedStep": copy.deepcopy(projected[2]) if not ordinary_repeated else None,
            "agreementSignatureProduced": True,
            "priorSelection": None,
            "priorJobId": None,
            "requestedAlternative": None,
            "requestedJobId": None,
            "authorizationState": "not-requested",
            "reconciliation": {
                "jobId": job_id,
                "railRefHash": digest(selected_ref),
                "phaseIndex": payout_indexes[0],
            },
        },
        "bundle": {
            "evidenceBoundFaultBundleVersion": "1",
            "jobId": job_id,
            "outcome": "completed",
            "anchoredByRole": "buyer",
            "listingRef": {},
            "agreementRef": {"contentHash": ""},
            "phaseSummary": [
                {"index": index, "kind": phase["kind"], "outcome": "ok"}
                for index, phase in enumerate(projected)
            ],
            "settlementEvidence": [
                {"phaseIndex": index, "phase": phase["kind"]}
                for index, phase in enumerate(projected)
                if phase["kind"].startswith(("pay-", "deliver-"))
            ],
        },
        "keys": {role: public_key(role) for role in SEEDS},
    }
    sign_all(value)
    return value


def sign_all(value: dict) -> None:
    for resolution in value.get("registry", {}).get("resolutions", []):
        definition = resolution.get("definition")
        if isinstance(definition, dict):
            definition.pop("signature", None)
            definition["signature"] = {
                "algorithm": "ed25519",
                "signer": STEWARD,
                "value": signature("steward", "dacs-rail:v1:", definition),
            }

    listing = value.get("listing")
    if isinstance(listing, dict):
        listing.pop("signature", None)
        listing["signature"] = {
            "algorithm": "ed25519",
            "signer": SELLER,
            "value": signature("seller", "dacs-listing:v1:", listing),
        }
    listing_hash = digest(unsigned(listing, "signature"))

    agreement = value.get("agreement")
    agreement["listingRef"] = {
        "listingId": listing["listingId"],
        "version": listing["listingVersion"],
        "contentHash": listing_hash,
    }
    agreement.pop("signatures", None)
    if value.get("runtime", {}).get("agreementSignatureProduced"):
        body = unsigned(agreement, "signatures")
        agreement["signatures"] = [
            {
                "party": CLAIMS[role],
                "algorithm": "ed25519",
                "value": signature(role, "dacs-payee-bound-agreement:v1:", body),
            }
            for role in ("buyer", "seller")
        ]
    else:
        agreement["signatures"] = []
    agreement_hash = digest(unsigned(agreement, "signatures"))

    bundle = value.get("bundle")
    if isinstance(bundle, dict):
        bundle["jobId"] = agreement["jobId"]
        bundle["listingRef"] = copy.deepcopy(agreement["listingRef"])
        bundle["agreementRef"] = {"contentHash": agreement_hash}
        bundle.pop("signatures", None)
        body = {name: item for name, item in bundle.items()
                if name not in {"signatures", "anchoredByRole"}}
        bundle["signatures"] = [
            {
                "party": CLAIMS[role],
                "algorithm": "ed25519",
                "value": signature(role, "dacs-evidence-bound-fault-bundle:v1:", body),
            }
            for role in ("buyer", "seller")
        ]


def set_selection(value: dict, ref: dict, handler: str, *, job_id: str | None = None) -> None:
    agreement = value["agreement"]
    agreement["terms"]["rail"] = copy.deepcopy(ref)
    if job_id is not None:
        agreement["jobId"] = job_id
    pipeline = effective_pipeline(value["listing"], ref, handler)
    pay_indexes = [
        index for index, phase in enumerate(pipeline)
        if phase["kind"].startswith("pay-")
    ]
    agreement["terms"]["price"]["currency"] = "DEM" if handler == "pay-dem" else "USDC"
    agreement["terms"]["payoutBindings"] = [
        {
            "railId": ref["railId"],
            "phaseIndex": index,
            "payeeAddress": SELLER,
        }
        for index in pay_indexes
    ]
    value["runtime"]["projectedStep"] = copy.deepcopy(pipeline[pay_indexes[0]])
    value["runtime"]["reconciliation"] = {
        "jobId": agreement["jobId"],
        "railRefHash": digest(ref),
        "phaseIndex": pay_indexes[0],
    }
    value["bundle"]["phaseSummary"] = [
        {"index": index, "kind": phase["kind"], "outcome": "ok"}
        for index, phase in enumerate(pipeline)
    ]
    value["bundle"]["settlementEvidence"] = [
        {"phaseIndex": index, "phase": phase["kind"]}
        for index, phase in enumerate(pipeline)
        if phase["kind"].startswith(("pay-", "deliver-"))
    ]


def add_case(cases: list[dict], name: str, expected: str, rule: str, note: str,
             mutate=None, *, base: str = "dem", operation: str = "execute",
             reason: str | None = None) -> None:
    value = make_base(
        "x402" if base == "x402" else "dem",
        ordinary_repeated=base == "repeated",
    )
    if mutate:
        mutate(value)
    sign_all(value)
    case = {
        "name": name,
        "expected": expected,
        "rule": rule,
        "operation": operation,
        "note": note,
        "base": base,
        **value,
    }
    if reason is not None:
        case["expectedReason"] = reason
    cases.append(case)


def build_cases() -> list[dict]:
    cases: list[dict] = []
    add_case(cases, "select-dem-projects-pay-dem", "pass", "APR-1..APR-5",
             "the complete DEM ref projects to pay-dem at the original phase index")
    add_case(cases, "select-x402-projects-pay-x402", "pass", "APR-1..APR-5",
             "the complete x402 ref projects to pay-x402 at the original phase index",
             base="x402")

    def reorder(v):
        v["listing"]["pipeline"][2]["parameters"]["alternatives"].reverse()
    add_case(cases, "alternative-array-order-does-not-select", "pass", "APR-3",
             "reversing display order does not change the complete signed x402 selection",
             reorder, base="x402")

    def unpinned_version(v):
        ref = copy.deepcopy(X402_REF)
        ref.pop("railVersion")
        v["listing"]["pipeline"][2]["parameters"]["alternatives"][1] = copy.deepcopy(ref)
        v["listing"]["acceptedRails"][1] = copy.deepcopy(ref)
        v["registry"]["resolutions"][1]["ref"] = copy.deepcopy(ref)
        set_selection(v, ref, "pay-x402")
    add_case(cases, "unpinned-version-uses-snapshot-selection", "pass", "APR-2/APR-3",
             "an omitted optional railVersion selects the authenticated snapshot version",
             unpinned_version, base="x402")

    add_case(cases, "duplicate-alternative-rejected", "fail", "APR-1",
             "full-canonical duplicate alternatives are malformed",
             lambda v: v["listing"]["pipeline"][2]["parameters"].update({
                 "alternatives": [copy.deepcopy(DEM_REF), copy.deepcopy(DEM_REF)]
             }), reason="alternative-duplicate")
    add_case(cases, "singleton-alternative-rejected", "fail", "APR-1",
             "an alternative slot requires at least two choices",
             lambda v: v["listing"]["pipeline"][2]["parameters"].update({
                 "alternatives": [copy.deepcopy(DEM_REF)]
             }), reason="alternative-cardinality")
    add_case(cases, "alternative-absent-from-accepted-rails", "fail", "APR-1",
             "every complete alternative must occur in acceptedRails",
             lambda v: v["listing"].update({"acceptedRails": [copy.deepcopy(DEM_REF)]}),
             reason="alternative-membership")
    add_case(cases, "duplicate-accepted-ref-rejected", "fail", "APR-1/LRR-1",
             "acceptedRails remains full-canonical duplicate-free",
             lambda v: v["listing"]["acceptedRails"].append(copy.deepcopy(DEM_REF)),
             reason="accepted-duplicate")
    add_case(cases, "two-alternative-slots-rejected", "fail", "APR-1",
             "v1 permits exactly one choice slot",
             lambda v: v["listing"]["pipeline"].insert(3, copy.deepcopy(v["listing"]["pipeline"][2])),
             reason="alternative-slot-cardinality")
    add_case(cases, "alternative-plus-concrete-pay-rejected", "fail", "APR-1/PIPE-5",
             "the choice slot cannot be combined with a concrete payment sibling",
             lambda v: v["listing"]["pipeline"].insert(3, {
                 "kind": "pay-dem", "parameters": {"rail": DEM_REF["railId"]}
             }), reason="alternative-concrete-sibling")
    add_case(cases, "bare-rail-parameter-on-alternative-rejected", "fail", "APR-1/LRR-1",
             "pay-alternative cannot be coerced to a railId-only concrete phase",
             lambda v: v["listing"]["pipeline"][2].update({
                 "parameters": {"rail": DEM_REF["railId"]}
             }), reason="alternative-parameters")

    add_case(cases, "unauthenticated-registry-is-indeterminate", "indeterminate", "APR-2/LRR-5",
             "unauthenticated registry authority cannot establish alternatives",
             lambda v: v["registry"].update({"authorityAuthenticated": False}),
             operation="validate-listing", reason="registry-authority")
    add_case(cases, "unavailable-definition-is-indeterminate", "indeterminate", "APR-2/LRR-5",
             "unavailable exact definition keeps the Listing indeterminate",
             lambda v: v["registry"]["resolutions"][1].update({"status": "unavailable"}),
             operation="validate-listing", reason="definition-unavailable")
    add_case(cases, "authenticated-missing-definition-rejected", "fail", "APR-2",
             "authenticated absence is a conclusive contradiction",
             lambda v: v["registry"]["resolutions"].pop(),
             operation="validate-listing", reason="definition-missing")
    add_case(cases, "resolution-snapshot-substitution-rejected", "fail", "APR-2",
             "all alternatives resolve through one authenticated snapshot",
             lambda v: v["registry"]["resolutions"][1].update({"snapshotId": "attacker-snapshot"}),
             operation="validate-listing", reason="registry-snapshot")
    add_case(cases, "recursive-alternative-handler-rejected", "fail", "APR-2/APR-8",
             "pay-alternative is never a registry phaseHandler",
             lambda v: v["registry"]["resolutions"][1]["definition"].update({
                 "phaseHandler": "pay-alternative"
             }), operation="validate-listing", reason="handler-unsupported")
    add_case(cases, "unknown-handler-rejected", "fail", "APR-2",
             "an unknown concrete handler cannot enter the choice set",
             lambda v: v["registry"]["resolutions"][1]["definition"].update({
                 "phaseHandler": "pay-future"
             }), operation="validate-listing", reason="handler-unsupported")
    add_case(cases, "locally-unsupported-handler-rejected", "fail", "APR-2",
             "the reader must support every resolved alternative handler",
             lambda v: v["runtime"].update({"supportedHandlers": ["pay-dem"]}),
             operation="validate-listing", reason="handler-unsupported")

    def outside_same_id(v):
        ref = copy.deepcopy(X402_REF)
        ref["parameters"]["resource"] = "https://attacker.example/pay"
        set_selection(v, ref, "pay-x402")
    add_case(cases, "same-railid-different-full-ref-rejected", "fail", "APR-3",
             "railId equality cannot cross-satisfy a different complete ref",
             outside_same_id, reason="selection-membership")

    add_case(cases, "selected-disabled-definition-rejected", "fail", "APR-3/RAV-R2",
             "the selected exact definition must pass RAV at session start",
             lambda v: v["registry"]["resolutions"][0]["definition"].update({
                 "availability": "disabled"
             }), reason="selected-availability")
    add_case(cases, "nonselected-disabled-does-not-select-or-fallback", "pass", "APR-2/APR-3",
             "a valid but disabled nonselected definition does not replace DEM",
             lambda v: v["registry"]["resolutions"][1]["definition"].update({
                 "availability": "disabled"
             }))
    add_case(cases, "caller-projected-handler-mismatch-rejected", "fail", "APR-4",
             "caller projection cannot override the authenticated handler",
             lambda v: v["runtime"].update({
                 "projectedStep": {"kind": "pay-x402", "parameters": {"rail": DEM_REF["railId"]}}
             }), reason="projection-mismatch")
    add_case(cases, "payout-selected-rail-mismatch-rejected", "fail", "APR-5",
             "the payout key must use the selected railId",
             lambda v: v["agreement"]["terms"]["payoutBindings"][0].update({
                 "railId": X402_REF["railId"]
             }), reason="payout-binding")
    add_case(cases, "payout-original-index-mismatch-rejected", "fail", "APR-5",
             "the payout key preserves the projection slot index",
             lambda v: v["agreement"]["terms"]["payoutBindings"][0].update({
                 "phaseIndex": 3
             }), reason="payout-binding")

    add_case(cases, "bundle-placeholder-kind-rejected", "fail", "APR-5/APR-7",
             "phaseSummary records the concrete handler, not pay-alternative",
             lambda v: v["bundle"]["phaseSummary"][2].update({"kind": "pay-alternative"}),
             operation="verify-bundle", reason="bundle-effective-pipeline")
    add_case(cases, "evidence-placeholder-kind-rejected", "fail", "APR-5/APR-7",
             "SettlementEvidence cannot claim pay-alternative execution",
             lambda v: v["bundle"]["settlementEvidence"][0].update({
                 "phase": "pay-alternative"
             }), operation="verify-bundle", reason="evidence-effective-pipeline")
    add_case(cases, "bundle-wrong-concrete-handler-rejected", "fail", "APR-7",
             "DACS-5 recomputes rather than trusting another concrete handler",
             lambda v: v["bundle"]["phaseSummary"][2].update({"kind": "pay-x402"}),
             operation="verify-bundle", reason="bundle-effective-pipeline")

    def pre_signature_reselection(v):
        set_selection(v, X402_REF, "pay-x402")
        v["runtime"].update({
            "agreementSignatureProduced": False,
            "priorSelection": copy.deepcopy(DEM_REF),
            "requestedAlternative": copy.deepcopy(X402_REF),
        })
    add_case(cases, "pre-signature-reselection-allowed", "pass", "APR-6",
             "before any Agreement signature the buyer may choose another valid alternative",
             pre_signature_reselection, operation="select-draft")

    def signed_switch(v):
        v["runtime"]["requestedAlternative"] = copy.deepcopy(X402_REF)
    add_case(cases, "same-job-post-signature-switch-rejected", "fail", "APR-6",
             "a signed selection cannot change inside the same job",
             signed_switch, operation="retry", reason="fresh-job-required")

    def fresh_job(v):
        set_selection(v, X402_REF, "pay-x402", job_id=JOB_X402)
        v["runtime"].update({
            "priorSelection": copy.deepcopy(DEM_REF),
            "priorJobId": JOB_DEM,
        })
    add_case(cases, "post-signature-switch-with-fresh-job", "pass", "APR-6",
             "a new signed Agreement under a fresh job may select x402",
             fresh_job, base="x402")

    def post_authorization(v):
        v["runtime"].update({
            "authorizationState": "submitted",
            "requestedAlternative": copy.deepcopy(X402_REF),
        })
    add_case(cases, "post-authorization-fallback-rejected", "fail", "APR-6",
             "submitted authorization cannot fall through to another rail",
             post_authorization, operation="retry", reason="fallback-forbidden")

    def indeterminate_fallback(v):
        v["runtime"].update({
            "authorizationState": "indeterminate",
            "requestedAlternative": copy.deepcopy(X402_REF),
        })
    add_case(cases, "indeterminate-settlement-fallback-rejected", "fail", "APR-6",
             "non-observation cannot authorize a second rail",
             indeterminate_fallback, operation="retry", reason="fallback-forbidden")

    def fresh_job_indeterminate_fallback(v):
        v["runtime"].update({
            "authorizationState": "indeterminate",
            "requestedAlternative": copy.deepcopy(X402_REF),
            "requestedJobId": JOB_X402,
        })
    add_case(cases, "fresh-job-cannot-mask-indeterminate-fallback", "fail", "APR-6",
             "a new job identifier cannot relabel recovery while the first rail is ambiguous",
             fresh_job_indeterminate_fallback, operation="retry", reason="fallback-forbidden")
    add_case(cases, "same-rail-retry-reconciles-without-authorization", "pass", "APR-6",
             "retry retains the selected tuple and performs reconciliation only",
             lambda v: v["runtime"].update({"authorizationState": "indeterminate"}),
             operation="retry", reason="reconciliation-pending")

    add_case(cases, "legacy-reader-refuses-unknown-choice-phase", "fail", "APR-8",
             "an old reader rejects rather than dropping pay-alternative",
             lambda v: v["runtime"].update({"readerSupportsPayAlternative": False}),
             operation="validate-listing", reason="unsupported-phase")
    add_case(cases, "ordinary-repeated-pay-retains-pipe5", "pass", "APR-8/PIPE-5",
             "an ordinary two-payment pipeline remains two independent DEM invocations",
             base="repeated", operation="validate-pipeline")
    return cases


def diff_ops(base: object, target: object, path: tuple = ()) -> list[dict]:
    if type(base) is not type(target):
        return [{"op": "replace", "path": list(path), "value": target}]
    if isinstance(base, dict):
        operations: list[dict] = []
        for name in sorted(set(base) - set(target)):
            operations.append({"op": "remove", "path": list(path + (name,))})
        for name in sorted(set(target) - set(base)):
            operations.append({
                "op": "add", "path": list(path + (name,)), "value": target[name]
            })
        for name in sorted(set(base) & set(target)):
            operations.extend(diff_ops(base[name], target[name], path + (name,)))
        return operations
    if isinstance(base, list):
        if len(base) != len(target):
            return [{"op": "replace", "path": list(path), "value": target}]
        operations: list[dict] = []
        for index, (left, right) in enumerate(zip(base, target)):
            operations.extend(diff_ops(left, right, path + (index,)))
        return operations
    if base != target:
        return [{"op": "replace", "path": list(path), "value": target}]
    return []


def compact_case(case: dict, fixtures: dict[str, dict]) -> dict:
    material = {name: item for name, item in case.items() if name not in CASE_FIELDS}
    compact = {
        "name": case["name"],
        "expected": case["expected"],
        "rule": case["rule"],
        "operation": case["operation"],
        "note": case["note"],
        "base": case["base"],
        "patch": diff_ops(fixtures[case["base"]], material),
    }
    if "expectedReason" in case:
        compact["expectedReason"] = case["expectedReason"]
    return compact


def build() -> dict:
    fixtures = {
        "dem": make_base("dem"),
        "x402": make_base("x402"),
        "repeated": make_base("dem", ordinary_repeated=True),
    }
    vectors = [compact_case(case, fixtures) for case in build_cases()]
    return {
        "set": "alternative-payment-projection-v0.1",
        "spec": "DACS-1 §6.3.4 LRR; DACS-3 §8.5.2; DACS-4 §9.9.1 APR-1..APR-8; DACS-5 §10.4.3",
        "fixtureModel": {
            "materialization": "deep-copy fixtures[vector.base], then apply vector.patch in order",
            "path": "array of object member names or zero-based array indexes",
            "operations": ["add", "remove", "replace"],
            "signatureRule": "patches contain every changed deterministic artifact signature",
        },
        "fixtures": fixtures,
        "count": len(vectors),
        "hash": hashlib.sha256(json.dumps(
            vectors, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")).hexdigest(),
        "vectors": vectors,
    }


def encoded(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    wanted = encoded(build())
    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
    if args.write:
        OUTPUT.write_text(wanted, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if current != wanted:
        print("alternative-payment vectors are stale; run generator with --write")
        return 1
    print("alternative-payment vectors OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
