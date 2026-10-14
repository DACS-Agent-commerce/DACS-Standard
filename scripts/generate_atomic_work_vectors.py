#!/usr/bin/env python3
"""Generate the six Atomic DACS Work candidate security-vector sets.

The corpus is intentionally implementation-neutral.  Authenticated synthetic
witnesses use fixed, public Ed25519 test seeds; nothing here is a live Demos
node receipt or a claim that a runtime already implements CORE §5.2.

Usage:
  python3 scripts/generate_atomic_work_vectors.py --write
  python3 scripts/generate_atomic_work_vectors.py --check
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import difflib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import atomic_work_reference as ref  # noqa: E402


VECTOR_DIR = ROOT / "conformance" / "vectors" / "security"
SET_SPECS = {
    "atomic-work-identity-v0.1": "CORE §5.2 AW-1..AW-29, AW-76..AW-77",
    "atomic-work-authorization-v0.1": "CORE §5.2 AW-30..AW-38",
    "atomic-work-execution-recovery-v0.1": "CORE §5.2 AW-39..AW-75",
    "atomic-work-purchase-completion-v0.1": "DACS-3 §8.6.1 AWP-1..AWP-21",
    "atomic-work-settlement-slot-v0.1": "DACS-4 §9.5.10 and §9.7.3 AWS-1..AWS-29",
    "atomic-work-audit-role-v0.1": "DACS-5 §10.4.2 AWB-1..AWB-10",
}

ATOMIC_RULES = {
    *{f"AW-{index}" for index in range(1, 78)},
    *{f"AWP-{index}" for index in range(1, 22)},
    *{f"AWS-{index}" for index in range(1, 30)},
    *{f"AWB-{index}" for index in range(1, 11)},
}

# Polarity means the vector's final verdict class, not whether the test itself
# is useful.  These exclusions prevent an honest indeterminate rule, a
# conditional later-version rule, or a producer-scope rule from being padded
# with a fake acceptance/rejection merely to fill a matrix cell.
POLARITY_NOT_APPLICABLE = {
    "P": {
        "AW-42": "The required result for an unauthenticated local observation is indeterminate, never acceptance.",
        **{
            f"AWB-{index}": "Atomic v1 admits no Work-carried bundle-anchor operation; the conditional later-profile path cannot have an acceptance fixture yet."
            for index in range(3, 8)
        },
        "AWP-17": "A positive ordinary failure record requires the existing production DACS failure/bundle verifier, not a synthetic Atomic fixture.",
        "AWP-18": "A positive refund requires a separately published and verified SettlementAmendment fixture outside this Atomic corpus.",
        "AWP-19": "No escrow or delivery-gated Atomic profile is standardized, so a positive guarantee would invent a new profile.",
        "AWS-13": "The required result for an indeterminate attempt observation is to hold the slot and remain indeterminate.",
    },
    "N": {
        "AW-13": "Any schema-valid operation array order is authoritative; receipt/execution divergence is rejected under AW-46/AW-51 instead.",
        "AW-15": "Transport fields are outside unsignedIntent by construction; an unknown intent member is intentionally hashed under AW-14 rather than treated as transport metadata.",
        "AW-42": "Ordinary not-found/timeout/local expiry must remain indeterminate rather than be coerced to rejection.",
        "AW-49": "Unavailable receipt reconstruction is indeterminate; contradictory receipt bytes are rejected by AW-46/AW-50.",
        "AW-64": "Post-commit receipt-service unavailability must remain indeterminate, not rejection.",
        **{
            f"AWB-{index}": "Atomic v1 admits no Work-carried bundle-anchor operation; cryptographic pass/fail fixtures require the later profile that defines its bytes."
            for index in range(3, 8)
        },
        "AWP-12": "Unavailable Atomic co-finality selects the sequential gate and remains indeterminate; it is not a rejection of the session.",
        "AWS-13": "An indeterminate attempt observation must hold the slot rather than produce a rejection verdict.",
    },
}

# A true boundary is a quantitative edge or a decision edge between lifecycle,
# discriminator, proof-availability, or version/profile states.  Ordinary
# binary signature and hash bindings still require positive and negative
# vectors, but do not acquire a meaningless `boundary: true` marker.
BOUNDARY_APPLICABLE_RULES = {
    "AW-9", "AW-21", "AW-40", "AW-42", "AW-43", "AW-44", "AW-49",
    "AW-51", "AW-58", "AW-60", "AW-61", "AW-62", "AW-63", "AW-64",
    "AW-71", "AW-74", "AW-75", "AW-76",
    "AWP-3", "AWP-5", "AWP-8", "AWP-12", "AWP-15", "AWP-17",
    "AWP-18", "AWP-19", "AWP-20", "AWP-21",
    "AWS-2", "AWS-7", "AWS-8", "AWS-11", "AWS-12", "AWS-13",
    "AWS-16", "AWS-17", "AWS-23", "AWS-24", "AWS-25", "AWS-28",
    "AWB-2", "AWB-3", "AWB-4", "AWB-5", "AWB-6", "AWB-7",
    "AWB-8", "AWB-10",
}

SEEDS = {
    "network": bytes.fromhex("11" * 32),
    "buyer": bytes.fromhex("22" * 32),
    "seller": bytes.fromhex("33" * 32),
    "orchestrator": bytes.fromhex("44" * 32),
    "payer": bytes.fromhex("55" * 32),
    "alternate-seller": bytes.fromhex("66" * 32),
}
CLAIMS = {role: f"did:dacs:test:{role}" for role in SEEDS}
PUBLIC_KEYS = {
    CLAIMS[role]: ref.b64u(ref.ed25519_public_key(seed))
    for role, seed in SEEDS.items()
    if role != "alternate-seller"
}
ALTERNATE_SELLER_PUBLIC_KEY = ref.b64u(
    ref.ed25519_public_key(SEEDS["alternate-seller"])
)
TEST_RAIL_ID = "demos-native:DEM"
COMPOSED_PROOF_RESERVATION_BYTES = 23_900


def claim(role: str) -> str:
    return CLAIMS[role]


def role_for_claim(value: str) -> str:
    return next(role for role, candidate in CLAIMS.items() if candidate == value)


def seed_for_claim(value: str) -> bytes:
    return SEEDS[role_for_claim(value)]


def mutate(value: Any, path: list[Any], replacement: Any) -> Any:
    out = copy.deepcopy(value)
    cursor = out
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = replacement
    return out


def noncanonical_b64u_alias(value: str) -> str:
    """Return a different unpadded spelling that permissively decodes identically."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if len(value) % 4 not in {2, 3}:
        raise ValueError("Base64URL value has no unused trailing bits")
    unused_mask = 0x0F if len(value) % 4 == 2 else 0x03
    index = alphabet.index(value[-1])
    if index & unused_mask:
        raise ValueError("input is already non-canonical")
    return value[:-1] + alphabet[index | 1]


def sign_embedded_unchecked(
    value: dict[str, Any], role: str, domain: bytes, *, field: str = "signature"
) -> dict[str, Any]:
    """Sign an intentionally non-CF-1 negative fixture without reference guards."""
    out = copy.deepcopy(value)
    out.pop(field, None)
    digest = ref.sha256_hex(ref.canonicalize(out).encode("utf-8"))
    out[field] = {
        "algorithm": "ed25519", "signer": CLAIMS[role],
        "value": ref.b64u(ref.ed25519_sign(
            SEEDS[role], domain + digest.encode("ascii")
        )),
    }
    return out


def sign_authorization_unchecked(
    value: dict[str, Any], role: str
) -> dict[str, Any]:
    out = copy.deepcopy(value)
    out.pop("value", None)
    digest = ref.sha256_hex(ref.canonicalize(out).encode("utf-8"))
    out["value"] = ref.b64u(ref.ed25519_sign(
        SEEDS[role], ref.AUTH_DOMAIN + digest.encode("ascii")
    ))
    return out


def artifact(kind: str, role: str, body: dict[str, Any]) -> dict[str, Any]:
    value = {
        "artifactVersion": "1",
        "kind": kind,
        "body": body,
        "contentHash": ref.sha256_hex(ref.jcs_bytes(body)),
    }
    return ref.sign_embedded(
        value, CLAIMS[role], SEEDS[role], ref._ARTIFACT_TEST_DOMAIN
    )


def rail_definition(rail_id: str) -> dict[str, Any]:
    """Return the complete signed native-DEM RailDefinition test fixture."""
    value = {
        "railVersion": 1,
        "railId": rail_id,
        "railType": "demos-native",
        "asset": {"kind": "native-dem", "symbol": "DEM", "decimals": 9},
        "network": {"kind": "demos"},
        "phaseHandler": "pay-dem",
        "parameters": {},
        "availability": "live",
        "governance": {
            "proposedBy": CLAIMS["network"],
            "acceptedAt": 1_799_999_700_000,
            "anchoring": "single-signer",
        },
    }
    return ref.sign_embedded(
        value, CLAIMS["network"], SEEDS["network"], ref._RAIL_DOMAIN
    )


def encoded_evidence(
    kind: str, value: dict[str, Any], role: str, domain: bytes
) -> dict[str, str]:
    signed = ref.sign_embedded(value, CLAIMS[role], SEEDS[role], domain)
    return {"kind": kind, "value": ref.b64u(ref.jcs_bytes(signed))}


def role_roster(seller_role: str = "seller") -> list[dict[str, Any]]:
    return [
        {"role": "buyer", "signer": claim("buyer")},
        {"role": "seller", "signer": claim(seller_role)},
        {"role": "orchestrator", "signer": claim("orchestrator")},
        {"role": "payer", "signer": claim("payer"), "nativeAccount": "dem-test-payer"},
    ]


# Extra BundleClaim values appended to one party's IdentityBundle while a
# fixture is built, keyed by (scope, role).  The "session" scope is the bundle
# bound by Vet records, the agreement, payment input, SessionContext source and
# current-profile admission; the "listing" scope is the Listing seller identity.
# Every dependent hash and signature is therefore re-derived from the variant.
_EXTRA_BUNDLE_CLAIMS: dict[tuple[str, str], list[Any]] = {}


@contextlib.contextmanager
def extra_bundle_claims(scope: str, role: str, records: list[Any]):
    _EXTRA_BUNDLE_CLAIMS[(scope, role)] = copy.deepcopy(records)
    try:
        yield
    finally:
        del _EXTRA_BUNDLE_CLAIMS[(scope, role)]


def identity_bundle(
    role: str, extra_claims: list[str] | None = None, *, scope: str = "session",
) -> dict[str, Any]:
    claims = [CLAIMS[role], *(extra_claims or [])]
    claim_records: list[Any] = []
    for value in claims:
        record: dict[str, Any] = {"ref": value}
        if value == CLAIMS["payer"]:
            record["metadata"] = {"nativeAccount": "dem-test-payer"}
        elif value in {CLAIMS["seller"], CLAIMS["alternate-seller"]}:
            record["metadata"] = {
                "nativeAccount": (
                    "dem-test-seller"
                    if value == CLAIMS["seller"]
                    else "dem-test-alternate-seller"
                )
            }
        claim_records.append(record)
    claim_records.extend(
        copy.deepcopy(_EXTRA_BUNDLE_CLAIMS.get((scope, role), []))
    )
    unsigned: dict[str, Any] = {
        "bundleVersion": "1", "presentedBy": CLAIMS[role],
        "presentedAt": 1_799_999_000_000,
        "claims": claim_records,
    }
    digest = ref.sha256_hex(ref.jcs_bytes(unsigned))
    unsigned["presentation"] = {
        "kind": "per-claim",
        "signatures": [{
            "ref": CLAIMS[role],
            "signature": ref.b64u(ref.ed25519_sign(
                SEEDS[role], b"dacs-bundle-presentation:v1:" + digest.encode("ascii")
            )),
        }],
    }
    return unsigned


def composite_verification_record(job_id: str, role: str) -> dict[str, Any]:
    bundle = (
        identity_bundle("buyer", [CLAIMS["payer"]])
        if role == "buyer"
        else identity_bundle(role)
    )
    value = {
        "recordVersion": "1",
        "jobId": job_id,
        "evaluatedParty": bundle["presentedBy"],
        "bundleHash": ref._identity_bundle_hash(bundle),
        "requirementHash": ref.sha256_hex(ref.jcs_bytes({
            "required": [], "oneOf": [], "party": bundle["presentedBy"],
        })),
        "freshness": [],
        "supplementary": [],
        "dealSpecific": [],
        "overallDecision": "pass",
        "generatedAt": 1_799_999_920_000,
    }
    return ref.sign_embedded(
        value, CLAIMS["orchestrator"], SEEDS["orchestrator"],
        ref._COMPOSITE_DOMAIN,
    )


def vet_record_ref(
    job_id: str, role: str, record: dict[str, Any],
) -> dict[str, Any]:
    return {
        "anchor": {
            "kind": "storage-program",
            "locator": (
                f"dacs2:composite:{job_id}:"
                f"{ref.cf4_encode(CLAIMS[role])}"
            ),
        },
        "contentHash": ref.sha256_hex(ref.jcs_bytes(record)),
        "signer": record["signature"]["signer"],
    }


def listing_fixture(
    job_id: str = "01K1DPA0000000000000000000", *, payee_bound: bool = False,
    current_profile: bool = False,
) -> dict[str, Any]:
    del job_id  # listing bytes are intentionally reusable across sessions.
    deliverable = {
        "kind": "storage-program", "schemaUrl": "https://dacs.dev/result-v1.json",
        "expectedSizeBytes": len(b"deterministic-result-v1"), "accessModel": "public",
    }
    unsigned: dict[str, Any] = {
        "dacsVersion": "1", "listingVersion": 1, "listingId": "atomic-fixed-1",
        "seller": {
            "identity": identity_bundle("seller", scope="listing"),
            "displayName": "Atomic Seller",
        },
        "offering": {
            "title": "Deterministic result", "description": "Atomic vector fixture",
            "category": "test.atomic", "tags": ["atomic"], "deliverable": deliverable,
        },
        "buyerRequirement": {"requirementVersion": "1", "required": [], "party": CLAIMS["buyer"]},
        "pipeline": [
            {"kind": "negotiate-fixed-price"},
            {"kind": (
                "commit-identity-bound-payee-agreement" if current_profile
                else "commit-payee-bound-agreement" if payee_bound
                else "commit-agreement"
            )},
            {"kind": "pay-dem", "parameters": {"rail": TEST_RAIL_ID}},
            {"kind": "deliver-storage-program"},
        ],
        "pricing": {"kind": "fixed", "price": {"amount": "10", "currency": "DEM"}},
        "acceptedRails": [{"railId": TEST_RAIL_ID}],
        "terms": {"deadlineSecAfterCommit": 60},
        "validity": {"notBefore": 1_799_000_000_000, "notAfter": 1_800_000_060_000},
    }
    if current_profile:
        unsigned["revocationState"] = {
            "revocationStateRefVersion": "1",
            "anchor": {
                "kind": "storage-program",
                "locator": f"dacs1-revocations:{ref.cf4_encode(CLAIMS['seller'])}",
            },
            "contentHash": ref.sha256_hex(
                ref.jcs_bytes({"seller": CLAIMS["seller"], "sequence": 7})
            ),
        }
    digest = ref.sha256_hex(ref.jcs_bytes(unsigned))
    unsigned["signature"] = {
        "algorithm": "ed25519", "signer": CLAIMS["seller"],
        "value": ref.b64u(ref.ed25519_sign(
            SEEDS["seller"], ref._LISTING_DOMAIN + digest.encode("ascii")
        )),
    }
    return unsigned


def listing_hash(listing: dict[str, Any]) -> str:
    return ref.sha256_hex(ref.jcs_bytes({k: v for k, v in listing.items() if k != "signature"}))


def resign_listing(listing: dict[str, Any]) -> dict[str, Any]:
    unsigned = copy.deepcopy(listing)
    unsigned.pop("signature", None)
    digest = ref.sha256_hex(ref.jcs_bytes(unsigned))
    unsigned["signature"] = {
        "algorithm": "ed25519", "signer": CLAIMS["seller"],
        "value": ref.b64u(ref.ed25519_sign(
            SEEDS["seller"], ref._LISTING_DOMAIN + digest.encode("ascii")
        )),
    }
    return unsigned


def agreement_document(
    job_id: str, *, payee_bound: bool = False,
    current_profile: bool = False,
    payout_address: str = "dem-test-seller",
    payout_bindings: list[dict[str, Any]] | None = None,
    agreement_domain: bytes | None = None,
    vet_records: dict[str, dict[str, Any]] | None = None,
    vet_ref_overrides: dict[str, dict[str, Any]] | None = None,
    omit_vet_refs: set[str] | None = None,
    seller_role: str = "seller",
) -> dict[str, Any]:
    listing = listing_fixture(
        job_id, payee_bound=payee_bound, current_profile=current_profile
    )
    buyer_bundle = identity_bundle("buyer", [CLAIMS["payer"]])
    seller_bundle = identity_bundle(seller_role)
    deliverable = listing["offering"]["deliverable"]
    delivery_bytes = b"deterministic-result-v1"
    vet_records = vet_records or {
        role: composite_verification_record(job_id, role)
        for role in ("buyer", "seller")
    }
    vet_ref_overrides = vet_ref_overrides or {}
    unsigned: dict[str, Any] = {
        (
            "identityBoundPayeeAgreementVersion" if current_profile
            else "payeeBoundAgreementVersion" if payee_bound
            else "agreementVersion"
        ): "1",
        "jobId": job_id,
        "listingRef": {"listingId": listing["listingId"], "version": 1, "contentHash": listing_hash(listing)},
        "parties": [
            {"role": "buyer", "bundleHash": ref._identity_bundle_hash(buyer_bundle), "primaryClaim": CLAIMS["buyer"], "vetRecordRef": copy.deepcopy(vet_ref_overrides.get("buyer", vet_record_ref(job_id, "buyer", vet_records["buyer"])))},
            {"role": "seller", "bundleHash": ref._identity_bundle_hash(seller_bundle), "primaryClaim": CLAIMS[seller_role], "vetRecordRef": copy.deepcopy(vet_ref_overrides.get("seller", vet_record_ref(job_id, seller_role, vet_records["seller"])))},
        ],
        "terms": {
            "price": {"amount": "10", "currency": "DEM"},
            "rail": {"railId": TEST_RAIL_ID},
            "deliverable": {
                "deliverableType": deliverable["kind"],
                "hash": ref.sha256_hex(ref.jcs_bytes(deliverable)),
                "schemaUrl": deliverable["schemaUrl"],
            },
            "deadline": 1_800_000_060_000,
            "additionalTerms": {"atomicDelivery": {
                "logicalAddress": f"dacs4:deliverable:{job_id}",
                "contentHash": ref.sha256_hex(delivery_bytes),
            }},
        },
        "derivedFromPattern": "fixed-price", "generatedAt": 1_799_999_900_000,
    }
    for party in unsigned["parties"]:
        if party["role"] in (omit_vet_refs or set()):
            del party["vetRecordRef"]
    if payee_bound or current_profile:
        unsigned["terms"]["payoutBindings"] = copy.deepcopy(
            payout_bindings
            if payout_bindings is not None
            else [{
                "railId": TEST_RAIL_ID,
                "phaseIndex": 2,
                "payeeAddress": payout_address,
            }]
        )
    digest = ref.sha256_hex(ref.jcs_bytes(unsigned))
    if agreement_domain is None:
        agreement_domain = (
            ref._IDENTITY_BOUND_PAYEE_AGREEMENT_DOMAIN
            if current_profile
            else ref._PAYEE_BOUND_AGREEMENT_DOMAIN
            if payee_bound
            else ref._AGREEMENT_DOMAIN
        )
    unsigned["signatures"] = [
        {"party": CLAIMS[role], "algorithm": "ed25519", "value": ref.b64u(
            ref.ed25519_sign(SEEDS[role], agreement_domain + digest.encode("ascii"))
        )}
        for role in ("buyer", seller_role)
    ]
    return unsigned


def finality_commitment(job_id: str, agreement: dict[str, Any]) -> dict[str, Any]:
    value = {
        "finalityCommitmentVersion": "1", "jobId": job_id,
        "agreementHash": ref._agreement_hash(agreement),
        "listingRef": copy.deepcopy(agreement["listingRef"]),
        "parties": [CLAIMS["buyer"], CLAIMS["seller"]],
        "pattern": "fixed-price", "createdAt": 1_799_999_950_000,
    }
    return ref.sign_embedded(value, CLAIMS["orchestrator"], SEEDS["orchestrator"], ref._COMMITMENT_DOMAIN)


def commitment_anchor_receipt(record: dict[str, Any]) -> dict[str, Any]:
    receipt = {
        "receiptVersion": "1", "substrate": "demos:testnet-atomic",
        "finalityProfile": "demos-bft-proof/test-1",
        "logicalAddress": f"dacs3:commit:{record['jobId']}",
        "nativeAddress": "stor-" + "a1" * 20,
        "contentHash": ref.sha256_hex(ref.jcs_bytes(record)),
        "transactionRef": {"kind": "demos-transaction", "value": "tx-commitment"},
        "writer": "native:relay-1", "nonce": "100", "state": "finalized",
        "observationDisposition": "established", "observedAt": 1_800_000_030_500,
        "blockRef": {"id": "block-atomic-901", "height": "901", "timestamp": 1_800_000_030_000},
    }
    receipt["evidence"] = encoded_evidence(
        "test-anchor-finality",
        {
            "logicalAddress": receipt["logicalAddress"],
            "nativeAddress": receipt["nativeAddress"],
            "contentHash": receipt["contentHash"],
            "transactionRef": receipt["transactionRef"],
            "writer": receipt["writer"],
            "nonce": receipt["nonce"],
            "state": receipt["state"],
            "blockRef": receipt["blockRef"],
            "networkId": receipt["substrate"],
            "proofProfile": receipt["finalityProfile"],
            "validatorSetId": "test-validator-set-1",
        },
        "network", ref._ANCHOR_TEST_DOMAIN,
    )
    return receipt


def registry_anchor_receipt(
    logical_address: str, value: dict[str, Any], *, label: str, nonce: str,
    block_timestamp: int = 1_799_999_750_000,
) -> dict[str, Any]:
    content_hash = ref.sha256_hex(ref.jcs_bytes(value))
    receipt = {
        "receiptVersion": "1",
        "substrate": "demos:testnet-atomic",
        "finalityProfile": "demos-bft-proof/test-1",
        "logicalAddress": logical_address,
        "nativeAddress": "stor-" + ref.sha256_hex(
            logical_address.encode("utf-8")
        )[:40],
        "contentHash": content_hash,
        "transactionRef": {
            "kind": "demos-transaction", "value": f"tx-{label}",
        },
        "writer": "native:registry-relay-1",
        "nonce": nonce,
        "state": "finalized",
        "observationDisposition": "established",
        "observedAt": block_timestamp + 1_000,
        "blockRef": {
            "id": f"block-{label}-750", "height": "750",
            "timestamp": block_timestamp,
        },
    }
    receipt["evidence"] = encoded_evidence(
        "test-anchor-finality",
        {
            "logicalAddress": receipt["logicalAddress"],
            "nativeAddress": receipt["nativeAddress"],
            "contentHash": receipt["contentHash"],
            "transactionRef": receipt["transactionRef"],
            "writer": receipt["writer"],
            "nonce": receipt["nonce"],
            "state": receipt["state"],
            "blockRef": receipt["blockRef"],
            "networkId": receipt["substrate"],
            "proofProfile": receipt["finalityProfile"],
            "validatorSetId": "test-validator-set-1",
        },
        "network", ref._ANCHOR_TEST_DOMAIN,
    )
    return receipt


def rail_registry_material(
    rail: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    rail_address = (
        f"dacs4:rail:{ref.cf4_encode(rail['railId'])}:"
        f"{rail['railVersion']}"
    )
    index = {
        "registryVersion": 1,
        "logicalAddress": "dacs4:registry:v0.1",
        "entries": [{
            "railId": rail["railId"],
            "latestVersion": rail["railVersion"],
            "versions": [{
                "railVersion": rail["railVersion"],
                "logicalAddress": rail_address,
                "contentHash": ref.sha256_hex(ref.jcs_bytes(rail)),
            }],
        }],
    }
    return (
        index,
        registry_anchor_receipt(
            index["logicalAddress"], index,
            label="rail-index", nonce="200",
        ),
        registry_anchor_receipt(
            rail_address, rail,
            label="rail-definition", nonce="201",
        ),
    )


def portable_session_context_source(intent: dict[str, Any]) -> dict[str, Any]:
    agreement = intent["operations"][2]["payload"]["artifact"]
    commitment = intent["operations"][3]["payload"]["artifact"]
    agreement_parties = {
        party["role"]: party for party in agreement["parties"]
    }
    seller_claim = agreement_parties["seller"]["primaryClaim"]
    seller_role = role_for_claim(seller_claim)
    return {
        "jobId": intent["jobId"],
        "listingRef": copy.deepcopy(agreement["listingRef"]),
        "recipeRegistryVersion": 1,
        "railRegistryVersion": 1,
        "parties": [
            {
                "role": "seller",
                "bundleHash": ref._identity_bundle_hash(identity_bundle(seller_role)),
                "primaryClaim": seller_claim,
                **({
                    "vetRecordRef": copy.deepcopy(
                        agreement_parties["seller"]["vetRecordRef"]
                    )
                } if "vetRecordRef" in agreement_parties["seller"] else {}),
            },
            {
                "role": "orchestrator",
                "bundleHash": ref._identity_bundle_hash(
                    identity_bundle("orchestrator")
                ),
                "primaryClaim": CLAIMS["orchestrator"],
            },
            {
                "role": "buyer",
                "bundleHash": ref._identity_bundle_hash(
                    identity_bundle("buyer", [CLAIMS["payer"]])
                ),
                "primaryClaim": CLAIMS["buyer"],
                **({
                    "vetRecordRef": copy.deepcopy(
                        agreement_parties["buyer"]["vetRecordRef"]
                    )
                } if "vetRecordRef" in agreement_parties["buyer"] else {}),
            },
        ],
        "priorPhaseOutputs": {
            "agreementHash": ref._agreement_hash(agreement),
            "commitmentHash": ref.sha256_hex(ref.jcs_bytes(commitment)),
        },
        "startedAt": 1_799_999_800_000,
    }


def atomic_payment_session_context_from_source(
    source: dict[str, Any],
) -> dict[str, Any]:
    by_role = {party["role"]: party for party in source["parties"]}
    return {
        "contextVersion": "1",
        "jobId": source["jobId"],
        "listingRef": copy.deepcopy(source["listingRef"]),
        "recipeRegistryVersion": source["recipeRegistryVersion"],
        "railRegistryVersion": source["railRegistryVersion"],
        "parties": [
            {
                "role": role,
                "primaryClaim": by_role[role]["primaryClaim"],
            }
            for role in ("buyer", "seller", "orchestrator")
        ],
        "priorPhaseOutputsHash": ref.sha256_hex(
            ref.jcs_bytes(source["priorPhaseOutputs"])
        ),
        "startedAt": source["startedAt"],
    }


def atomic_payment_session_context(intent: dict[str, Any]) -> dict[str, Any]:
    return atomic_payment_session_context_from_source(
        portable_session_context_source(intent)
    )


def payment_phase_input(intent: dict[str, Any]) -> dict[str, Any]:
    agreement = intent["operations"][2]["payload"]["artifact"]
    buyer_bundle = identity_bundle("buyer", [CLAIMS["payer"]])
    seller_party = next(
        party for party in agreement["parties"] if party["role"] == "seller"
    )
    seller_role = role_for_claim(seller_party["primaryClaim"])
    transfer = next(
        operation for operation in intent["operations"]
        if operation.get("kind") == "native-dem-transfer"
    )
    payee_address = transfer["payload"]["to"]
    return {
        "jobId": intent["jobId"], "agreement": copy.deepcopy(agreement),
        "rail": rail_definition(intent["railId"]),
        "payer": {"bundleHash": ref._identity_bundle_hash(buyer_bundle), "primaryClaim": CLAIMS["buyer"], "payingKey": CLAIMS["payer"]},
        "payee": {"bundleHash": seller_party["bundleHash"], "primaryClaim": seller_party["primaryClaim"], "payeeAddress": payee_address},
        "amount": {"amount": "10", "currency": "DEM"},
        "atomicSessionContext": atomic_payment_session_context(intent),
    }


def current_profile_admission(
    intent: dict[str, Any], authority: dict[str, Any]
) -> dict[str, Any]:
    """Authenticate the synthetic outputs of current RSC/IBH/Vet/LAA admission."""
    listing = authority["listing"]
    agreement = authority["agreement"]
    payer_bundle = authority["payerBundle"]
    payee_bundle = authority["payeeBundle"]
    state_ref = listing["revocationState"]
    listing_digest = listing_hash(listing)
    value = {
        "profile": copy.deepcopy(ref._CURRENT_PROFILE_TUPLE),
        "workId": ref.work_id(intent),
        "jobId": intent["jobId"],
        "listingHash": listing_digest,
        "agreementHash": ref._agreement_hash(agreement),
        "agreementArtifact": "identity-bound-payee",
        "commitPhase": "commit-identity-bound-payee-agreement",
        "payerBundleHash": ref._identity_bundle_hash(payer_bundle),
        "payeeBundleHash": ref._identity_bundle_hash(payee_bundle),
        "rsc": {
            "stateLine": copy.deepcopy(state_ref),
            "disposition": "active-current",
            "headContentHash": ref.sha256_hex(ref.jcs_bytes({
                "stateLine": state_ref,
                "listingHash": listing_digest,
                "profile": ref._CURRENT_PROFILE_TUPLE,
            })),
        },
        "ibhDisposition": "verified",
        "vetDisposition": "current-authorized",
        "laaDisposition": "current-eligible",
    }
    return encoded_evidence(
        "test-current-profile-admission",
        value,
        "network",
        ref._CURRENT_PROFILE_ADMISSION_TEST_DOMAIN,
    )


def resign_current_profile_admission(
    intent: dict[str, Any], authority: dict[str, Any]
) -> None:
    admission = authority["currentProfileAdmission"]
    subject = ref.verify_encoded_evidence(
        admission,
        "test-current-profile-admission",
        PUBLIC_KEYS,
        ref._CURRENT_PROFILE_ADMISSION_TEST_DOMAIN,
        expected_signer=CLAIMS["network"],
    )
    subject.pop("signature")
    authority["currentProfileAdmission"] = encoded_evidence(
        "test-current-profile-admission",
        subject,
        "network",
        ref._CURRENT_PROFILE_ADMISSION_TEST_DOMAIN,
    )


def mutate_current_profile_admission(
    authority: dict[str, Any], path: list[Any], value: Any,
) -> None:
    admission = authority["currentProfileAdmission"]
    subject = ref.verify_encoded_evidence(
        admission,
        "test-current-profile-admission",
        PUBLIC_KEYS,
        ref._CURRENT_PROFILE_ADMISSION_TEST_DOMAIN,
        expected_signer=CLAIMS["network"],
    )
    subject.pop("signature")
    subject = mutate(subject, path, value)
    authority["currentProfileAdmission"] = encoded_evidence(
        "test-current-profile-admission",
        subject,
        "network",
        ref._CURRENT_PROFILE_ADMISSION_TEST_DOMAIN,
    )


def authorization_authority(intent: dict[str, Any]) -> dict[str, Any]:
    agreement = intent["operations"][2]["payload"]["artifact"]
    payee_bound = "payeeBoundAgreementVersion" in agreement
    current_profile = "identityBoundPayeeAgreementVersion" in agreement
    record = intent["operations"][3]["payload"]["artifact"]
    rail = rail_definition(intent["railId"])
    rail_index, rail_index_receipt, rail_receipt = rail_registry_material(rail)
    session_source = portable_session_context_source(intent)
    atomic_context = atomic_payment_session_context(intent)
    seller_party = next(
        party for party in agreement["parties"] if party["role"] == "seller"
    )
    seller_role = role_for_claim(seller_party["primaryClaim"])
    authority = {
        "agreement": copy.deepcopy(agreement),
        "listing": listing_fixture(
            intent["jobId"], payee_bound=payee_bound,
            current_profile=current_profile,
        ),
        "payerBundle": identity_bundle("buyer", [CLAIMS["payer"]]),
        "payeeBundle": identity_bundle(seller_role),
        "paymentPhaseInput": payment_phase_input(intent),
        "finalityCommitment": copy.deepcopy(record),
        "commitmentReceipt": commitment_anchor_receipt(record),
        "networkAuthority": CLAIMS["network"],
        "railDefinition": rail,
        "railRegistryIndex": rail_index,
        "railRegistryIndexReceipt": rail_index_receipt,
        "railDefinitionReceipt": rail_receipt,
        "sessionContextSource": session_source,
        "sessionContextSourceEvidence": encoded_evidence(
            "test-session-context-source",
            {
                "sessionContextHash": ref.sha256_hex(
                    ref.jcs_bytes(session_source)
                ),
                "proofProfile": "demos-bft-proof/test-1",
                "validatorSetId": "test-validator-set-1",
            },
            "network", ref._SESSION_SOURCE_TEST_DOMAIN,
        ),
        "atomicSessionContext": atomic_context,
        "atomicSessionContextEvidence": encoded_evidence(
            "test-atomic-session-context",
            {
                "jobId": intent["jobId"],
                "contextHash": ref.sha256_hex(ref.jcs_bytes(atomic_context)),
                "proofProfile": "demos-bft-proof/test-1",
            },
            "orchestrator", ref._SESSION_CONTEXT_TEST_DOMAIN,
        ),
    }
    if current_profile:
        authority["currentProfileAdmission"] = current_profile_admission(
            intent, authority
        )
    return authority


def rebind_session_source_evidence(authority: dict[str, Any]) -> None:
    source = authority["sessionContextSource"]
    authority["sessionContextSourceEvidence"] = encoded_evidence(
        "test-session-context-source",
        {
            "sessionContextHash": ref.sha256_hex(ref.jcs_bytes(source)),
            "proofProfile": "demos-bft-proof/test-1",
            "validatorSetId": "test-validator-set-1",
        },
        "network", ref._SESSION_SOURCE_TEST_DOMAIN,
    )


def purchase_intent(
    job_id: str = "01K1DPA0000000000000000000", *, generation: int = 0,
    expected_state: str = "vacant", prior_failure: str | None = None,
    payee_bound: bool = False, current_profile: bool = False,
    payout_address: str = "dem-test-seller",
    payout_bindings: list[dict[str, Any]] | None = None,
    agreement_domain: bytes | None = None,
    vet_ref_overrides: dict[str, dict[str, Any]] | None = None,
    omit_agreement_vet_refs: set[str] | None = None,
    gate_mode: str = "co-final", seller_role: str = "seller",
) -> dict[str, Any]:
    buyer_vet = composite_verification_record(job_id, "buyer")
    seller_vet = composite_verification_record(job_id, seller_role)
    payee_account = (
        "dem-test-seller"
        if seller_role == "seller"
        else "dem-test-alternate-seller"
    )
    agreement = agreement_document(
        job_id, payee_bound=payee_bound, current_profile=current_profile,
        payout_address=payout_address,
        payout_bindings=payout_bindings, agreement_domain=agreement_domain,
        vet_records={"buyer": buyer_vet, "seller": seller_vet},
        vet_ref_overrides=vet_ref_overrides,
        omit_vet_refs=omit_agreement_vet_refs,
        seller_role=seller_role,
    )
    commitment = finality_commitment(job_id, agreement)
    slot_key = {"networkId": "demos:testnet-atomic", "railId": TEST_RAIL_ID, "jobId": job_id, "phaseIndex": 2}
    conflict = {
        **slot_key, "agreementHash": ref._agreement_hash(agreement),
        "commitmentLogicalAddress": f"dacs3:commit:{job_id}",
        "payer": "dem-test-payer", "payee": payee_account, "asset": "DEM", "amount": "10",
    }
    result = {
        "workVersion": "1",
        "executionProfile": "demos-bft-work/1",
        "profile": "dacs-purchase-v1",
        "gateMode": gate_mode,
        "networkId": "demos:testnet-atomic",
        "railId": TEST_RAIL_ID,
        "jobId": job_id,
        "phaseIndex": 2,
        "expiresAt": 1_800_000_060_000,
        "roleRoster": role_roster(seller_role),
        "operations": [
            {"operationId": "buyer-vet", "kind": "storage-program-put", "critical": True, "dependsOn": [], "requiredRoles": ["orchestrator"], "payload": {"artifact": buyer_vet, "logicalAddress": f"dacs2:composite:{job_id}:{ref.cf4_encode(buyer_vet['evaluatedParty'])}", "writeCondition": {"kind": "create-only"}}},
            {"operationId": "seller-vet", "kind": "storage-program-put", "critical": True, "dependsOn": [], "requiredRoles": ["orchestrator"], "payload": {"artifact": seller_vet, "logicalAddress": f"dacs2:composite:{job_id}:{ref.cf4_encode(seller_vet['evaluatedParty'])}", "writeCondition": {"kind": "create-only"}}},
            {"operationId": "agreement", "kind": "assert-artifact", "critical": True, "dependsOn": ["buyer-vet", "seller-vet"], "requiredRoles": ["orchestrator"], "payload": {"artifact": agreement}},
            {"operationId": "commitment", "kind": "storage-program-put", "critical": True, "dependsOn": ["agreement"], "requiredRoles": ["orchestrator"], "payload": {"artifact": commitment, "logicalAddress": f"dacs3:commit:{job_id}", "writeCondition": {"kind": "create-only"}}},
            {"operationId": "payment-slot", "kind": "payment-slot-cas", "critical": True, "dependsOn": ["commitment"], "requiredRoles": ["payer"], "payload": {"slotKey": slot_key, "expected": {"state": expected_state, "generation": generation}, "conflictDigest": ref.conflict_digest(conflict)}},
            {"operationId": "payment", "kind": "native-dem-transfer", "critical": True, "dependsOn": ["payment-slot"], "requiredRoles": ["payer"], "payload": {"from": "dem-test-payer", "to": payee_account, "asset": "DEM", "amount": "10"}},
        ],
    }
    if prior_failure is not None:
        result["priorFailureReceiptCommitment"] = prior_failure
    return result


def completion_intent(
    purchase_receipt: dict[str, Any], job_id: str = "01K1DPA0000000000000000000",
    *, gate_mode: str = "co-final",
) -> dict[str, Any]:
    delivery_bytes = b"deterministic-result-v1"
    return {
        "workVersion": "1",
        "executionProfile": "demos-bft-work/1",
        "profile": "dacs-completion-v1",
        "gateMode": gate_mode,
        "networkId": "demos:testnet-atomic",
        "railId": TEST_RAIL_ID,
        "jobId": job_id,
        "phaseIndex": 3,
        "expiresAt": 1_800_003_600_000,
        "roleRoster": role_roster(),
        "operations": [
            {"operationId": "purchase-receipt", "kind": "assert-work-receipt", "critical": True, "dependsOn": [], "requiredRoles": ["orchestrator"], "payload": {"receipt": purchase_receipt}},
            {"operationId": "delivery", "kind": "storage-program-put", "critical": True, "dependsOn": ["purchase-receipt"], "requiredRoles": ["seller"], "payload": {"bytes": ref.b64u(delivery_bytes), "contentHash": ref.sha256_hex(delivery_bytes), "logicalAddress": f"dacs4:deliverable:{job_id}", "writeCondition": {"kind": "create-only"}}},
        ],
    }


def capability() -> dict[str, Any]:
    value = {
        "capabilityVersion": "1",
        "networkAuthority": CLAIMS["network"],
        "networkId": "demos:testnet-atomic",
        "executionProfile": "demos-bft-work/1",
        "workVersions": ["1"],
        "profiles": ["dacs-purchase-v1", "dacs-completion-v1"],
        "operationKinds": sorted(ref.OP_KINDS),
        "payloadSchemas": copy.deepcopy(ref.PAYLOAD_SCHEMAS),
        "authorizationAlgorithms": ["ed25519"],
        "proofProfile": "demos-bft-proof/test-1",
        "validatorSetId": "test-validator-set-1",
        "limits": {
            "maxCanonicalBytes": 50_000,
            "maxOperations": 16,
            "maxExecutionTimeMs": 2_000,
            "maxProofBytes": 24_000,
            "feeRule": "test-fixed-fee",
        },
    }
    return sign_capability(value)


def sign_capability(value: dict[str, Any]) -> dict[str, Any]:
    """Authenticate an exact synthetic capability after intentional variants."""
    out = {k: copy.deepcopy(v) for k, v in value.items() if k != "evidence"}
    out["evidence"] = encoded_evidence(
        "test-network-capability-attestation",
        {"capabilityHash": ref.sha256_hex(ref.jcs_bytes(out))},
        "network", ref._CAPABILITY_TEST_DOMAIN,
    )
    return out


def authorizations(intent: dict[str, Any]) -> list[dict[str, Any]]:
    roster = {binding["role"]: binding["signer"] for binding in intent["roleRoster"]}
    result = []
    for index, operation in enumerate(intent["operations"]):
        for role in operation["requiredRoles"]:
            envelope = {
                "authorizationVersion": "1",
                "algorithm": "ed25519",
                "workId": ref.work_id(intent),
                "executionProfile": intent["executionProfile"],
                "networkId": intent["networkId"],
                "railId": intent["railId"],
                "jobId": intent["jobId"],
                "phaseIndex": intent["phaseIndex"],
                "operationId": operation["operationId"],
                "operationIndex": index,
                "operationKind": operation["kind"],
                "role": role,
                "signer": roster[role],
            }
            result.append(ref.sign_authorization(
                envelope, seed_for_claim(roster[role])
            ))
    return result


def ledger_evidence(
    attempt_id: str, work_id: str, state: str,
    native_transaction_ref: dict[str, str],
    *, nonce: str | None = None, fee: str = "1",
) -> dict[str, Any]:
    if nonce is None:
        suffix = attempt_id.removeprefix("attempt-")
        nonce = f"attempt-nonce-{suffix}"
    value = {
        "evidenceVersion": "test-1",
        "attemptId": attempt_id,
        "workId": work_id,
        "nativeTransactionRef": copy.deepcopy(native_transaction_ref),
        "state": state,
        "blockId": "block-901" if state.startswith("included-") else "block-900",
        "proofProfile": "demos-bft-proof/test-1",
        "validatorSetId": "test-validator-set-1",
        "nonce": nonce,
        "fee": fee,
    }
    return ref.sign_embedded(
        value, CLAIMS["network"], SEEDS["network"], ref._LEDGER_TEST_DOMAIN
    )


def effect_inventory(
    work_id: str, effects: list[tuple[str, dict[str, str]]],
    *, block_id: str = "block-atomic-901",
    proof_profile: str = "demos-bft-proof/test-1",
    validator_set_id: str = "test-validator-set-1",
) -> dict[str, Any]:
    """Network-signed Work-ledger inventory of every attempt whose business
    effect committed; a rolled-back Work records none."""
    value = {
        "inventoryVersion": "test-1",
        "workId": work_id,
        "blockId": block_id,
        "proofProfile": proof_profile,
        "validatorSetId": validator_set_id,
        "effectAttempts": [
            {"attemptId": attempt_id, "nativeTransactionRef": copy.deepcopy(native_ref)}
            for attempt_id, native_ref in effects
        ],
    }
    return ref.sign_embedded(
        value, CLAIMS["network"], SEEDS["network"], ref._LEDGER_INVENTORY_TEST_DOMAIN
    )


def with_effect_inventory(value: dict[str, Any], effect_ids: list[str]) -> dict[str, Any]:
    """Attach the ledger inventory naming the given presented attempts.

    The inventory is taken at the finalized receipt block or, without a
    receipt, at the block of the lifecycle evidence that resolves the Work:
    the included winner's, or the one block every presented evidence names.
    """
    out = dict(value)
    refs = {
        attempt.get("attemptId"): attempt.get("nativeTransactionRef")
        for attempt in out["attempts"] if isinstance(attempt, dict)
    }
    receipt = out.get("receipt")
    evidence = [
        attempt["lifecycleEvidence"] for attempt in out["attempts"]
        if isinstance(attempt, dict) and isinstance(attempt.get("lifecycleEvidence"), dict)
    ]
    included = [item for item in evidence if item["state"].startswith("included-")]
    blocks = {item["blockId"] for item in (included or evidence)}
    if isinstance(receipt, dict):
        block_id = receipt["blockRef"]["id"]
    elif len(blocks) == 1:
        block_id = blocks.pop()
    else:
        block_id = "block-atomic-901"
    out["ledgerInventory"] = effect_inventory(
        ref.work_id(out["intent"]),
        [(attempt_id, refs[attempt_id]) for attempt_id in effect_ids],
        block_id=block_id,
    )
    return out


def slot_proof(key: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    value = {
        "proofVersion": "test-1", "key": key, "state": state,
        "blockId": "block-slot-900",
        "proofProfile": "demos-bft-proof/test-1",
        "validatorSetId": "test-validator-set-1",
    }
    return ref.sign_embedded(
        value, CLAIMS["network"], SEEDS["network"], ref._LEDGER_TEST_DOMAIN
    )


def resign_ledger_proof(value: dict[str, Any]) -> dict[str, Any]:
    unsigned = {k: copy.deepcopy(v) for k, v in value.items() if k != "signature"}
    return ref.sign_embedded(
        unsigned, CLAIMS["network"], SEEDS["network"], ref._LEDGER_TEST_DOMAIN
    )


def operation_results(
    intent: dict[str, Any], outcome: str = "committed", failed_index: int | None = None
) -> list[dict[str, Any]]:
    results = []
    for index, operation in enumerate(intent["operations"]):
        if outcome == "committed":
            status = "committed"
        else:
            status = "rolled-back" if index <= int(failed_index) else "not-executed"
        leaf: dict[str, Any] = {
            "operationId": operation["operationId"],
            "operationIndex": index,
            "operationKind": operation["kind"],
            "inputHash": ref.sha256_hex(ref.jcs_bytes(operation["payload"])),
            "status": status,
        }
        if status == "committed":
            if operation["kind"] == "native-dem-transfer":
                leaf["outputHash"] = ref.sha256_hex(ref.jcs_bytes(operation["payload"]))
            elif operation["kind"] == "storage-program-put":
                payload = operation["payload"]
                content_hash = payload.get("contentHash")
                if content_hash is None and isinstance(payload.get("artifact"), dict):
                    content_hash = ref.sha256_hex(ref.jcs_bytes(payload["artifact"]))
                leaf["storageOutput"] = {
                    "logicalAddress": payload["logicalAddress"],
                    "nativeAddress": f"stor-{ref.sha256_hex((intent['jobId'] + ':' + operation['operationId']).encode())[:40]}",
                    "contentHash": content_hash,
                    "writer": "native:fee-payer-77",
                    "nonce": str(200 + index),
                }
                leaf["outputHash"] = ref.sha256_hex(ref.jcs_bytes(leaf["storageOutput"]))
            else:
                leaf["outputHash"] = ref.sha256_hex(ref.jcs_bytes({"accepted": True, "operationId": operation["operationId"]}))
        elif status == "rolled-back":
            leaf["errorCode"] = "atomic-test-failure" if index == failed_index else "atomic-rollback"
        results.append(leaf)
    return results


def final_receipt(
    intent: dict[str, Any], outcome: str = "committed", failed_index: int | None = None,
    block_timestamp: int = 1_800_000_030_000,
    prior_slot_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    results = operation_results(intent, outcome, failed_index)
    if intent["profile"] == "dacs-purchase-v1":
        slot_payload = next(op for op in intent["operations"] if op["kind"] == "payment-slot-cas")["payload"]
        slot_key = copy.deepcopy(slot_payload["slotKey"])
        slot_before = copy.deepcopy(prior_slot_state or slot_payload["expected"])
    else:
        prior_receipt = intent["operations"][0]["payload"]["receipt"]
        slot_key = copy.deepcopy(prior_receipt["paymentSlot"]["key"])
        slot_before = copy.deepcopy(prior_receipt["paymentSlot"]["after"])
    # Business roots cover economic/artifact state only. Payment-slot terminal
    # metadata is authoritative recovery state committed separately in the
    # receipt core, not a balance/artifact effect.
    pre_state: dict[str, Any] = {"balances": {"payer": "100", "seller": "0"}, "artifacts": []}
    if outcome == "committed":
        if intent["profile"] == "dacs-purchase-v1":
            terminal_generation = slot_payload["expected"]["generation"] + (
                1 if slot_payload["expected"]["state"] == "rolled-back" else 0
            )
            slot_after = {
                "state": "settled", "generation": terminal_generation,
                "workId": ref.work_id(intent), "conflictDigest": slot_payload["conflictDigest"],
            }
        else:
            slot_after = copy.deepcopy(slot_before)
        post_state = {
            "balances": (
                {"payer": "90", "seller": "10"}
                if intent["profile"] == "dacs-purchase-v1"
                else copy.deepcopy(pre_state["balances"])
            ),
            "artifacts": [r["operationId"] for r in results if "storageOutput" in r],
        }
    else:
        post_state = copy.deepcopy(pre_state)
        # A rolled-back Completion leaves the verified Purchase slot as is.
        slot_after = copy.deepcopy(slot_before)
    if outcome == "rolled-back" and intent["profile"] == "dacs-purchase-v1":
        terminal_generation = slot_payload["expected"]["generation"] + (
            1 if slot_payload["expected"]["state"] == "rolled-back" else 0
        )
        slot_after = {
            "state": "rolled-back", "generation": terminal_generation,
            "workId": ref.work_id(intent), "conflictDigest": slot_payload["conflictDigest"],
        }
    state_witness = ref.sign_embedded(
        {
            "preState": pre_state,
            "postState": post_state,
            "protectedKeys": ["balances", "artifacts"],
            "proofProfile": "demos-bft-proof/test-1",
            "validatorSetId": "test-validator-set-1",
        },
        CLAIMS["network"], SEEDS["network"], ref._STATE_TEST_DOMAIN,
    )
    receipt: dict[str, Any] = {
        "receiptVersion": "1",
        "executionProfile": intent["executionProfile"],
        "profile": intent["profile"],
        "networkId": intent["networkId"],
        "workId": ref.work_id(intent),
        "winningAttempt": {
            "attemptId": "attempt-a",
            "nativeTransactionRef": {"kind": "demos-transaction", "value": "tx-test-atomic-a"},
        },
        "blockRef": {"id": "block-atomic-901", "height": "901", "timestamp": block_timestamp},
        "outcome": outcome,
        "operationResults": results,
        "operationReceiptRoot": ref.operation_receipt_root(results),
        "businessState": {
            "preRoot": ref.state_root(pre_state),
            "postRoot": ref.state_root(post_state),
            "effectsRoot": ref.sha256_hex(ref.jcs_bytes({"pre": pre_state, "post": post_state})),
            "evidence": {
                "kind": "test-business-state-witness",
                "value": ref.b64u(ref.jcs_bytes(state_witness)),
            },
        },
        "paymentSlot": {
            "key": slot_key,
            "before": copy.deepcopy(slot_before),
            "after": copy.deepcopy(slot_after),
        },
        "envelopeEffects": {"nonceConsumed": True, "feeCharged": "1"},
    }
    if outcome == "rolled-back":
        receipt["failedOperationId"] = intent["operations"][int(failed_index)]["operationId"]
    commitment = ref._receipt_commitment(receipt)
    receipt["receiptCommitment"] = commitment
    if intent["profile"] == "dacs-purchase-v1":
        terminal_key = (
            "failureReceiptCommitment" if outcome == "rolled-back" else "receiptCommitment"
        )
        receipt["paymentSlot"]["after"][terminal_key] = commitment
    slot_subject = copy.deepcopy(receipt["paymentSlot"])
    if intent["profile"] == "dacs-purchase-v1":
        slot_subject["after"].pop("receiptCommitment", None)
        slot_subject["after"].pop("failureReceiptCommitment", None)
    receipt["slotStateEvidence"] = encoded_evidence(
        "test-payment-slot-state",
        {
            "slot": slot_subject,
            "networkId": intent["networkId"],
            "workId": receipt["workId"],
            "proofProfile": "demos-bft-proof/test-1",
            "validatorSetId": "test-validator-set-1",
        },
        "network", ref._SLOT_STATE_TEST_DOMAIN,
    )
    finality = {
        "kind": "test-bft-checkpoint",
        "networkId": intent["networkId"],
        "blockId": receipt["blockRef"]["id"],
        "receiptCommitment": commitment,
        "validatorSetId": "test-validator-set-1",
        "proofProfile": "demos-bft-proof/test-1",
    }
    receipt["finalityEvidence"] = encoded_evidence(
        "test-bft-checkpoint", finality, "network", ref._CHECKPOINT_TEST_DOMAIN
    )
    return receipt


def rebind_receipt_finality(receipt: dict[str, Any]) -> dict[str, Any]:
    """Recompute the synthetic test checkpoint after an intentional mutation."""
    out = copy.deepcopy(receipt)
    out.pop("finalityEvidence", None)
    out.pop("receiptCommitment", None)
    if out["profile"] == "dacs-purchase-v1":
        out["paymentSlot"]["after"].pop("receiptCommitment", None)
        out["paymentSlot"]["after"].pop("failureReceiptCommitment", None)
    commitment = ref._receipt_commitment(out)
    out["receiptCommitment"] = commitment
    if out["profile"] == "dacs-purchase-v1":
        terminal_key = (
            "failureReceiptCommitment" if out["outcome"] == "rolled-back"
            else "receiptCommitment"
        )
        out["paymentSlot"]["after"][terminal_key] = commitment
    slot_subject = copy.deepcopy(out["paymentSlot"])
    if out["profile"] == "dacs-purchase-v1":
        slot_subject["after"].pop("receiptCommitment", None)
        slot_subject["after"].pop("failureReceiptCommitment", None)
    out["slotStateEvidence"] = encoded_evidence(
        "test-payment-slot-state",
        {
            "slot": slot_subject, "networkId": out["networkId"],
            "workId": out["workId"], "proofProfile": "demos-bft-proof/test-1",
            "validatorSetId": "test-validator-set-1",
        },
        "network", ref._SLOT_STATE_TEST_DOMAIN,
    )
    finality = {
        "kind": "test-bft-checkpoint",
        "networkId": out["networkId"],
        "blockId": out["blockRef"]["id"],
        "receiptCommitment": commitment,
        "validatorSetId": "test-validator-set-1",
        "proofProfile": "demos-bft-proof/test-1",
    }
    out["finalityEvidence"] = encoded_evidence(
        "test-bft-checkpoint", finality, "network", ref._CHECKPOINT_TEST_DOMAIN
    )
    return out


def projected_anchor_fixture(
    intent: dict[str, Any], receipt: dict[str, Any], operation_index: int,
) -> dict[str, Any]:
    leaf = receipt["operationResults"][operation_index]
    storage = leaf["storageOutput"]
    path = ref.inclusion_path(receipt["operationResults"], operation_index)
    operation_ref = {
        "kind": "demos-work-operation-v1",
        "networkId": receipt["networkId"],
        "workId": receipt["workId"],
        "operationIndex": operation_index,
        "operationId": leaf["operationId"],
        "operationKind": leaf["operationKind"],
    }
    resolved = {
        "operationRef": operation_ref,
        "receiptContentHash": ref.receipt_hash(receipt),
        "leaf": leaf,
        "inclusionPath": path,
        "finalityEvidence": receipt["finalityEvidence"],
    }
    anchor = {
        "receiptVersion": "1",
        "substrate": receipt["networkId"],
        "finalityProfile": "demos-bft-proof/test-1",
        "logicalAddress": storage["logicalAddress"],
        "nativeAddress": storage["nativeAddress"],
        "contentHash": storage["contentHash"],
        "transactionRef": {
            "kind": "demos-work-operation-v1",
            "value": f"{receipt['workId']}/{leaf['operationId']}",
        },
        "writer": storage["writer"],
        "nonce": storage["nonce"],
        "state": "finalized",
        "observationDisposition": "established",
        "observedAt": receipt["blockRef"]["timestamp"] + 500,
        "blockRef": copy.deepcopy(receipt["blockRef"]),
        "evidence": {
            "kind": "demos-work-operation-proof-v1",
            "value": ref.b64u(ref.jcs_bytes(resolved)),
        },
    }
    return {
        "operationEvidence": {"leaf": leaf, "inclusionPath": path},
        "anchorReceipt": anchor,
    }


def vector(
    name: str, rules: list[str], surface: str, input_value: dict[str, Any],
    expected: str, reason: str, *, boundary: bool = False,
    boundary_rules: list[str] | None = None,
) -> dict[str, Any]:
    input_value = copy.deepcopy(input_value)
    if surface in {"purchase-admission", "completion-admission", "authorization", "attempts", "receipt", "lifecycle", "projection", "profile", "slot", "settlement", "role-anchor", "audit", "limits"}:
        input_value.setdefault("capability", capability())
        input_value.setdefault("expectedNetworkAuthority", CLAIMS["network"])
        input_value.setdefault("expectedProofProfile", "demos-bft-proof/test-1")
        input_value.setdefault("expectedRailRegistryAuthority", CLAIMS["network"])
    if surface == "attempts" and isinstance(input_value.get("intent"), dict):
        input_value.setdefault("authority", authorization_authority(input_value["intent"]))
    if surface == "slot" and isinstance(input_value.get("work", {}).get("intent"), dict):
        slot_intent = input_value["work"]["intent"]
        if slot_intent.get("profile") == "dacs-purchase-v1":
            input_value.setdefault("slotAuthority", authorization_authority(slot_intent))
    result = {
        "name": name,
        "ruleRefs": rules,
        "caseClass": {
            "pass": "acceptance", "fail": "rejection",
            "indeterminate": "indeterminate", "error": "malformed",
        }[expected],
        "surface": surface,
        "input": input_value,
        "expected": expected,
        "reason": reason,
    }
    if boundary_rules is not None:
        if not boundary_rules or not set(boundary_rules).issubset(rules):
            raise AssertionError("boundaryRuleRefs must be a non-empty ruleRefs subset")
        result["boundary"] = True
        result["boundaryRuleRefs"] = boundary_rules
    elif boundary:
        result["boundary"] = True
        result["boundaryRuleRefs"] = copy.deepcopy(rules)
    return result


def rename_operation(intent: dict[str, Any], index: int, operation_id: str) -> dict[str, Any]:
    """Rename one operation and its dependency references for grammar edges."""
    out = copy.deepcopy(intent)
    previous = out["operations"][index]["operationId"]
    out["operations"][index]["operationId"] = operation_id
    for operation in out["operations"]:
        operation["dependsOn"] = [
            operation_id if dependency == previous else dependency
            for dependency in operation["dependsOn"]
        ]
    return out


def intent_with_operation_count(intent: dict[str, Any], count: int) -> dict[str, Any]:
    """Extend a valid intent with independent deterministic assertion operations."""
    out = copy.deepcopy(intent)
    fixture = copy.deepcopy(next(
        operation["payload"]
        for operation in out["operations"]
        if operation["kind"] == "assert-artifact"
    ))
    while len(out["operations"]) < count:
        index = len(out["operations"])
        out["operations"].append({
            "operationId": f"limit-{index}",
            "kind": "assert-artifact",
            "critical": True,
            "dependsOn": [],
            "requiredRoles": ["orchestrator"],
            "payload": copy.deepcopy(fixture),
        })
    return out


def intent_with_canonical_size(intent: dict[str, Any], size: int) -> dict[str, Any]:
    """Pad an intent with ASCII so its JCS representation is exactly ``size`` bytes."""
    out = copy.deepcopy(intent)
    out["boundaryPadding"] = ""
    padding_size = size - len(ref.jcs_bytes(out))
    if padding_size < 0:
        raise ValueError("requested canonical size is smaller than the base intent")
    out["boundaryPadding"] = "x" * padding_size
    if len(ref.jcs_bytes(out)) != size:
        raise AssertionError("ASCII boundary padding did not reach the exact JCS size")
    return out


def proof_material_with_canonical_size(size: int) -> dict[str, Any]:
    """Build synthetic proof material whose canonical JCS size is exact."""
    proof = {"proofVersion": "test-1", "padding": ""}
    padding_size = size - len(ref.jcs_bytes(proof))
    if padding_size < 0:
        raise ValueError("requested canonical size is smaller than proof envelope")
    proof["padding"] = "x" * padding_size
    if len(ref.jcs_bytes(proof)) != size:
        raise AssertionError("proof padding did not reach the exact JCS size")
    return proof


def identity_vectors() -> list[dict[str, Any]]:
    intent = purchase_intent()
    cap = capability()
    common_cap = {
        "capability": cap,
        "expectedNetworkAuthority": CLAIMS["network"],
        "publicKeys": PUBLIC_KEYS,
        "networkId": intent["networkId"],
        "executionProfile": intent["executionProfile"],
        "profile": intent["profile"],
        "expectedProofProfile": "demos-bft-proof/test-1",
        "stage": "pre-sign",
        "mode": "atomic",
        "fallback": False,
        "businessWorks": 2,
        "auditTail": True,
        "claimsExactlyTwoLifecycleTransactions": False,
    }
    invalid_cap = mutate(cap, ["networkId"], "demos:othernet")
    buyer_cap = copy.deepcopy(cap)
    buyer_cap["networkAuthority"] = CLAIMS["buyer"]
    buyer_cap = {k: v for k, v in buyer_cap.items() if k != "evidence"}
    buyer_cap["evidence"] = encoded_evidence(
        "test-network-capability-attestation",
        {"capabilityHash": ref.sha256_hex(ref.jcs_bytes(buyer_cap))},
        "buyer", ref._CAPABILITY_TEST_DOMAIN,
    )
    no_work_versions = copy.deepcopy(cap); no_work_versions["workVersions"] = []; no_work_versions = sign_capability(no_work_versions)
    no_algorithms = copy.deepcopy(cap); no_algorithms["authorizationAlgorithms"] = []; no_algorithms = sign_capability(no_algorithms)
    wrong_proof_profile = copy.deepcopy(cap); wrong_proof_profile["proofProfile"] = "attacker-proof/1"; wrong_proof_profile = sign_capability(wrong_proof_profile)
    missing_proof_limit = copy.deepcopy(cap); del missing_proof_limit["limits"]["maxProofBytes"]; missing_proof_limit = sign_capability(missing_proof_limit)
    reordered = mutate(intent, ["roleRoster"], list(reversed(intent["roleRoster"])))
    duplicate_role = mutate(intent, ["roleRoster"], intent["roleRoster"] + [intent["roleRoster"][0]])
    future_dep = mutate(intent, ["operations", 0, "dependsOn"], ["agreement"])
    unknown_kind = mutate(intent, ["operations", 0, "kind"], "http-post")
    noncritical = mutate(intent, ["operations", 0, "critical"], False)
    bad_opid = mutate(intent, ["operations", 0, "operationId"], "0-not-valid")
    bad_roles = mutate(intent, ["operations", 5, "requiredRoles"], ["payer", "payer"])
    runtime = mutate(intent, ["operations", 0, "payload"], {"$runtime": "MutableSdkObject"})
    # The candidate set itself must remain valid JCS JSON.  Exercise a type
    # violation instead of embedding an out-of-JCS-range integer in the corpus.
    unsafe = mutate(intent, ["expiresAt"], "9007199254740992")
    safe_integer_max = mutate(intent, ["expiresAt"], ref.SAFE_INT_MAX)
    operation_id_max = rename_operation(intent, 0, "a" * 64)
    operation_id_too_long = rename_operation(intent, 0, "a" * 65)
    unknown_member = copy.deepcopy(intent)
    unknown_member["futureExtension"] = {"preserved": True}
    schema_capability_input = {**common_cap, "intent": intent}
    missing_schema_capability = copy.deepcopy(cap)
    del missing_schema_capability["payloadSchemas"]["native-dem-transfer"]
    missing_schema_capability = sign_capability(missing_schema_capability)
    unsupported_schema_capability = copy.deepcopy(cap)
    unsupported_schema_capability["payloadSchemas"]["native-dem-transfer"] = (
        "dacs-atomic-payload/native-dem-transfer/v2"
    )
    unsupported_schema_capability = sign_capability(unsupported_schema_capability)
    missing_amount_intent = copy.deepcopy(intent)
    del missing_amount_intent["operations"][5]["payload"]["amount"]
    empty_validator_set = copy.deepcopy(cap)
    empty_validator_set["validatorSetId"] = ""
    empty_validator_set = sign_capability(empty_validator_set)
    unsupported_fee_rule = copy.deepcopy(cap)
    unsupported_fee_rule["limits"]["feeRule"] = "attacker-fee-rule"
    unsupported_fee_rule = sign_capability(unsupported_fee_rule)
    duplicate_algorithm = copy.deepcopy(cap)
    duplicate_algorithm["authorizationAlgorithms"] = ["ed25519", "ed25519"]
    duplicate_algorithm = sign_capability(duplicate_algorithm)
    extra_capability_member = copy.deepcopy(cap)
    extra_capability_member["futureTrustGate"] = True
    extra_capability_member = sign_capability(extra_capability_member)
    bool_limit = copy.deepcopy(cap)
    bool_limit["limits"]["maxOperations"] = True
    bool_limit = sign_capability(bool_limit)
    non_nfc_capability_evidence = copy.deepcopy(cap)
    decoded_capability_evidence = json.loads(ref.b64u_decode(
        non_nfc_capability_evidence["evidence"]["value"]
    ).decode("utf-8"))
    decoded_capability_evidence["unknown"] = "e\u0301"
    decoded_capability_evidence = sign_embedded_unchecked(
        decoded_capability_evidence, "network", ref._CAPABILITY_TEST_DOMAIN
    )
    non_nfc_capability_evidence["evidence"]["value"] = ref.b64u(
        json.dumps(
            decoded_capability_evidence, ensure_ascii=False,
            separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
    )
    negative_phase_index = mutate(intent, ["phaseIndex"], -1)
    negative_expiry = mutate(intent, ["expiresAt"], -1)
    parameter_identity = copy.deepcopy(intent)
    parameter_identity["roleRoster"][0]["signer"] = (
        CLAIMS["buyer"] + "?a=1&z=2"
    )
    unsorted_parameters = copy.deepcopy(intent)
    unsorted_parameters["roleRoster"][0]["signer"] = (
        CLAIMS["buyer"] + "?z=2&a=1"
    )
    non_nfc_claim = copy.deepcopy(intent)
    non_nfc_claim["roleRoster"][0]["signer"] = "did:dacs:te\u0301st:buyer"
    non_nfc_unknown = copy.deepcopy(intent)
    non_nfc_unknown["futureLabel"] = "e\u0301"
    canonical_domain_claim = copy.deepcopy(intent)
    canonical_domain_claim["roleRoster"][0]["signer"] = "domain:example.com"
    uppercase_domain_claim = copy.deepcopy(intent)
    uppercase_domain_claim["roleRoster"][0]["signer"] = "domain:EXAMPLE.COM"
    return [
        vector("aw-capability-authenticated", ["AW-1", "AW-4", "AW-5", "AW-19", "AW-20", "AW-27"], "capability", common_cap, "pass", "Authenticated exact capability pins the execution profile, permits two business Works plus an audit tail, and supplies node rather than preflight authority."),
        vector("aw-capability-mismatch-pre-sign-fallback", ["AW-1", "AW-2"], "capability", {**common_cap, "capability": invalid_cap, "mode": "legacy", "fallback": True}, "pass", "Before signing, a missing/mismatched capability selects the existing lifecycle."),
        vector("aw-capability-mismatch-no-fallback", ["AW-1", "AW-2"], "capability", {**common_cap, "capability": invalid_cap}, "fail", "Atomic execution cannot begin under a mismatched capability."),
        vector("aw-capability-wrong-authority", ["AW-1"], "capability", {**common_cap, "capability": buyer_cap}, "fail", "A buyer-resigned attestation cannot substitute for the capability's authenticated network authority."),
        vector("aw-capability-work-version-missing", ["AW-1"], "capability", {**common_cap, "capability": no_work_versions}, "fail", "Capability admission requires Work v1 in the authenticated workVersions set."),
        vector("aw-capability-authorization-algorithm-missing", ["AW-1", "AW-30"], "capability", {**common_cap, "capability": no_algorithms}, "fail", "Capability admission requires the authorization algorithm actually used."),
        vector("aw-capability-proof-profile-mismatch", ["AW-1", "AW-48"], "capability", {**common_cap, "capability": wrong_proof_profile}, "fail", "The authenticated capability proof profile must equal the selected profile."),
        vector("aw-capability-proof-byte-limit-missing", ["AW-1", "AW-71"], "capability", {**common_cap, "capability": missing_proof_limit}, "fail", "Authenticated Atomic capability limits include a positive maxProofBytes bound."),
        vector("aw-capability-validator-set-empty", ["AW-1", "AW-48"], "capability", {**common_cap, "capability": empty_validator_set}, "fail", "The authenticated validator-set binding is non-empty and schema-validated."),
        vector("aw-capability-fee-rule-unsupported", ["AW-1", "AW-56", "AW-71"], "capability", {**common_cap, "capability": unsupported_fee_rule}, "fail", "A verifier rejects an authenticated fee rule it does not implement."),
        vector("aw-capability-authorization-algorithm-duplicate", ["AW-1", "AW-30"], "capability", {**common_cap, "capability": duplicate_algorithm}, "fail", "Atomic v1 admits exactly one canonical Ed25519 algorithm entry."),
        vector("aw-capability-closed-extension", ["AW-1", "AW-77"], "capability", {**common_cap, "capability": extra_capability_member}, "fail", "Unknown trust-gate members require a new capability version rather than open interpretation."),
        vector("aw-capability-boolean-limit", ["AW-1", "AW-71"], "capability", {**common_cap, "capability": bool_limit}, "fail", "A JSON boolean cannot exploit Python integer equality in a capability limit."),
        vector("aw-capability-evidence-string-not-nfc", ["AW-1", "AW-8"], "capability", {**common_cap, "capability": non_nfc_capability_evidence}, "fail", "A cryptographically valid capability attestation still fails when a preserved signed member violates recursive CF-1 NFC."),
        vector("aw-signed-atomic-stays-atomic", ["AW-3"], "capability", {**common_cap, "stage": "signed"}, "pass", "After signing, an Atomic Work remains on the Atomic path under the authenticated capability."),
        vector("aw-no-silent-fallback-after-sign", ["AW-3"], "capability", {**common_cap, "stage": "signed", "mode": "legacy", "fallback": True}, "fail", "A signed Atomic Work cannot silently fall back to a payment path."),
        vector("aw-not-exactly-two-lifecycle-transactions", ["AW-4", "AW-5"], "capability", {**common_cap, "claimsExactlyTwoLifecycleTransactions": True}, "fail", "The audit finalisation tail prevents an exactly-two lifecycle transaction claim."),
        vector("aw-canonical-intent-and-id", ["AW-6", "AW-7", "AW-8", "AW-11", "AW-12", "AW-13", "AW-16", "AW-17", "AW-18"], "intent", {"intent": intent, "claimedWorkId": ref.work_id(intent)}, "pass", "Pure JSON with unique ordered roles is JCS-canonicalized, and its exact canonical bytes are accepted only under the derived identifier."),
        vector("aw-runtime-object-marker-rejected", ["AW-6", "AW-7"], "intent", {"intent": runtime}, "fail", "A runtime/SDK object marker is neither the closed pure-JSON intent shape nor portable signed data."),
        vector("aw-safe-integer-max-accepted", ["AW-9"], "intent", {"intent": safe_integer_max}, "pass", "The inclusive RFC 8785 safe-integer maximum remains valid pure JSON.", boundary=True),
        vector("aw-safe-integer-bound", ["AW-9"], "intent", {"intent": unsafe}, "fail", "Unsafe JSON integers fail before canonicalization."),
        vector("aw-negative-phase-index", ["AW-9", "AW-74"], "intent", {"intent": negative_phase_index}, "fail", "A phase index is a non-negative safe integer in schema and semantics."),
        vector("aw-negative-expiry", ["AW-9", "AW-58"], "intent", {"intent": negative_expiry}, "fail", "An expiry timestamp is a non-negative safe integer in schema and semantics."),
        vector("aw-claim-parameters-canonical", ["AW-8", "AW-10"], "intent", {"intent": parameter_identity}, "pass", "A CF-2 ClaimReference with sorted canonical parameters is accepted as signed bytes."),
        vector("aw-claim-parameters-unsorted", ["AW-8", "AW-10"], "intent", {"intent": unsorted_parameters}, "fail", "Unsorted ClaimReference parameters are rejected rather than silently repaired after signing."),
        vector("aw-claim-identifier-not-nfc", ["AW-8", "AW-10"], "intent", {"intent": non_nfc_claim}, "fail", "A non-NFC ClaimReference identifier is rejected before hashing."),
        vector("aw-unknown-member-string-not-nfc", ["AW-8", "AW-14"], "intent", {"intent": non_nfc_unknown}, "fail", "CF-1 recursively rejects a non-NFC string even in a preserved unknown signed member."),
        vector("aw-domain-claim-canonical-a-label", ["AW-8", "AW-10"], "intent", {"intent": canonical_domain_claim}, "pass", "The test CF-2 parser accepts a canonical lowercase domain A-label identifier."),
        vector("aw-domain-claim-uppercase-rejected", ["AW-8", "AW-10"], "intent", {"intent": uppercase_domain_claim}, "fail", "The test CF-2 parser rejects a domain identifier that violates DCR-1 lowercase canonical form."),
        vector("aw-role-roster-order", ["AW-10", "AW-11"], "intent", {"intent": reordered}, "fail", "Role roster ordering is part of the deterministic wire contract."),
        vector("aw-role-roster-duplicate", ["AW-10", "AW-11"], "intent", {"intent": duplicate_role}, "fail", "A role cannot occur twice."),
        vector("aw-required-role-order-and-unique", ["AW-12"], "intent", {"intent": bad_roles}, "fail", "Operation role requirements are canonical and unique."),
        vector("aw-object-member-order-stable", ["AW-8", "AW-13", "AW-14"], "intent", {"intent": json.loads(json.dumps(intent, sort_keys=True)), "claimedWorkId": ref.work_id(intent)}, "pass", "Object member insertion order does not affect JCS or workId; operation array order remains fixed."),
        vector("aw-unknown-member-affects-id", ["AW-14", "AW-16"], "identity-compare", {"leftIntent": intent, "rightIntent": unknown_member}, "pass", "Unknown preserved unsigned members remain inside canonical Work bytes."),
        vector("aw-transport-fields-outside-work-id", ["AW-15"], "intent", {"intent": intent, "claimedWorkId": ref.work_id(intent), "attemptId": "not-hashed", "outerFee": "99"}, "pass", "Transport metadata outside the intent does not enter canonicalWorkBytes."),
        vector("aw-claimed-id-mismatch", ["AW-16", "AW-17"], "intent", {"intent": intent, "claimedWorkId": "00" * 32}, "fail", "Caller-supplied IDs are recomputed and mismatches rejected."),
        vector("aw-different-id-identical-bytes", ["AW-18"], "intent", {"intent": intent, "claimedWorkId": "ff" * 32}, "fail", "Identical canonical bytes cannot be admitted under a second identity."),
        vector("aw-execution-profile-bound", ["AW-19", "AW-20"], "capability", {**common_cap, "executionProfile": "demos-bft-work/other"}, "fail", "An unsupported execution-profile interpretation is rejected before execution."),
        vector("aw-valid-operation-graph", ["AW-21", "AW-22", "AW-23", "AW-24", "AW-25", "AW-26", "AW-28", "AW-29"], "intent", {"intent": intent}, "pass", "The signed array uses only critical deterministic v1 kinds and forms a valid earlier-dependency execution graph."),
        vector("aw-operation-id-max-length", ["AW-21"], "intent", {"intent": operation_id_max}, "pass", "A 64-character operation ID is the last valid grammar length.", boundary=True),
        vector("aw-operation-id-over-max-length", ["AW-21"], "intent", {"intent": operation_id_too_long}, "fail", "A 65-character operation ID crosses the fixed grammar boundary.", boundary=True),
        vector("aw-operation-id-grammar", ["AW-21"], "intent", {"intent": bad_opid}, "fail", "Operation IDs follow the fixed grammar."),
        vector("aw-future-dependency-rejected", ["AW-22", "AW-23"], "intent", {"intent": future_dep}, "fail", "Future/self/unknown dependencies are rejected before execution."),
        vector("aw-critical-only", ["AW-24", "AW-26"], "intent", {"intent": noncritical}, "fail", "All v1 effects participate in one critical business overlay."),
        vector("aw-closed-operation-kind", ["AW-25", "AW-28", "AW-29"], "intent", {"intent": unknown_kind}, "fail", "An HTTP-like external operation cannot enter the closed rollback-covered set."),
        vector("aw-preflight-not-node-proof", ["AW-27"], "capability", {**common_cap, "capability": invalid_cap, "simulationPassed": True}, "fail", "A client simulation cannot substitute for authenticated node capability."),
        vector("aw-expiry-last-valid-millisecond", ["AW-76"], "expiry", {"intent": intent, "consensusTransitionTime": intent["expiresAt"] - 1, "executedOperationCount": 1}, "pass", "Consensus may begin execution at the final millisecond strictly before expiresAt.", boundary=True),
        vector("aw-expiry-equality-rejected-before-op", ["AW-76"], "expiry", {"intent": intent, "consensusTransitionTime": intent["expiresAt"], "executedOperationCount": 0}, "fail", "At expiresAt equality the Work is expired and no operation executes.", boundary=True),
        vector("aw-payload-schema-exact-profile", ["AW-77"], "capability", schema_capability_input, "pass", "The authenticated execution profile advertises and applies one exact v1 schema for every admitted operation kind."),
        vector("aw-payload-schema-kind-missing", ["AW-77"], "capability", {**schema_capability_input, "capability": missing_schema_capability}, "fail", "A capability missing the native-transfer payload schema cannot admit the Purchase Work."),
        vector("aw-payload-schema-version-unsupported", ["AW-77"], "capability", {**schema_capability_input, "capability": unsupported_schema_capability}, "fail", "An authenticated but unsupported payload-schema version fails before authorization or execution."),
        vector("aw-payload-schema-no-caller-inference", ["AW-77"], "capability", {**schema_capability_input, "intent": missing_amount_intent, "callerState": {"amount": "10"}}, "fail", "A missing signed transfer amount cannot be inferred from caller or SDK state."),
    ]


def authorization_vectors() -> list[dict[str, Any]]:
    # Exercise the ordinary finalized-commitment authority chain on this
    # focused surface; composed admission separately covers co-final mode.
    intent = purchase_intent(gate_mode="sequential")
    auths = authorizations(intent)
    authority = authorization_authority(intent)
    base = {"intent": intent, "authorizations": auths, "publicKeys": PUBLIC_KEYS, "authority": authority}
    tampered = mutate(auths, [0, "networkId"], "demos:evilnet")
    wrong_index = mutate(auths, [0, "operationIndex"], 1)
    other_work = mutate(auths, [0, "workId"], "00" * 32)
    missing = auths[1:]
    outer = copy.deepcopy(base)
    outer["outerSubmitter"] = CLAIMS["buyer"]
    outer_cannot_fill_missing = copy.deepcopy(base)
    outer_cannot_fill_missing["authorizations"] = auths[1:]
    outer_cannot_fill_missing["outerSubmitter"] = auths[0]["signer"]
    wrong_signer = mutate(auths, [-1, "signer"], claim("orchestrator"))
    wrong_role = mutate(auths, [-1, "role"], "orchestrator")
    bad_algorithm = mutate(auths, [0, "algorithm"], "rsa")
    ecdsa_relabel = mutate(auths, [0, "algorithm"], "ecdsa-secp256k1")
    sr1_relabel = mutate(auths, [0, "algorithm"], "sr1-aggregate")
    bool_phase_index = mutate(auths, [0, "phaseIndex"], True)
    bool_operation_index = mutate(auths, [0, "operationIndex"], True)
    bad_signature = mutate(auths, [0, "value"], ref.b64u(b"\0" * 64))
    alias_signature = mutate(
        auths, [0, "value"], noncanonical_b64u_alias(auths[0]["value"])
    )
    short_signature = mutate(auths, [0, "value"], ref.b64u(b"\0" * 63))
    short_public_keys = copy.deepcopy(PUBLIC_KEYS)
    short_public_keys[auths[0]["signer"]] = ref.b64u(b"\0" * 31)
    wrong_network_capability = mutate(capability(), ["networkId"], "demos:evilnet")
    wrong_network_capability = sign_capability(wrong_network_capability)
    wrong_execution_capability = mutate(
        capability(), ["executionProfile"], "demos-bft-work/other"
    )
    wrong_execution_capability = sign_capability(wrong_execution_capability)
    wrong_profile_capability = copy.deepcopy(capability())
    wrong_profile_capability["profiles"] = ["dacs-completion-v1"]
    wrong_profile_capability = sign_capability(wrong_profile_capability)
    wrong_schema_capability = mutate(
        capability(), ["payloadSchemas", "native-dem-transfer"],
        "https://attacker.invalid/native-transfer.json",
    )
    wrong_schema_capability = sign_capability(wrong_schema_capability)
    duplicate_kind_capability = copy.deepcopy(capability())
    duplicate_kind_capability["operationKinds"].append(
        duplicate_kind_capability["operationKinds"][0]
    )
    duplicate_kind_capability = sign_capability(duplicate_kind_capability)
    wrong_proof_capability = mutate(
        capability(), ["proofProfile"], "attacker-proof/1"
    )
    wrong_proof_capability = sign_capability(wrong_proof_capability)
    forged_intent = copy.deepcopy(intent)
    forged_intent["roleRoster"][1]["signer"] = CLAIMS["buyer"]
    forged_auths = authorizations(forged_intent)
    for index, authorization in enumerate(forged_auths):
        if authorization["role"] == "seller":
            forged_auths[index] = ref.sign_authorization(
                {k: v for k, v in authorization.items() if k != "value"}, SEEDS["buyer"]
            )
    missing_authority = copy.deepcopy(base)
    del missing_authority["authority"]
    parameter_intent = copy.deepcopy(intent)
    parameter_intent["roleRoster"][0]["signer"] = CLAIMS["buyer"] + "?a=1"
    parameter_authority = authorization_authority(parameter_intent)
    parameter_auths = authorizations(parameter_intent)
    missing_anchor_nonce = copy.deepcopy(base)
    missing_nonce_receipt = missing_anchor_nonce["authority"]["commitmentReceipt"]
    del missing_nonce_receipt["nonce"]
    missing_nonce_proof = json.loads(
        ref.b64u_decode(missing_nonce_receipt["evidence"]["value"]).decode("utf-8")
    )
    missing_nonce_proof.pop("nonce")
    missing_nonce_proof = ref.sign_embedded(
        {k: v for k, v in missing_nonce_proof.items() if k != "signature"},
        CLAIMS["network"], SEEDS["network"], ref._ANCHOR_TEST_DOMAIN,
    )
    missing_nonce_receipt["evidence"]["value"] = ref.b64u(
        ref.jcs_bytes(missing_nonce_proof)
    )
    mismatched_payment_session = copy.deepcopy(base)
    mismatched_payment_session["authority"]["paymentPhaseInput"][
        "atomicSessionContext"
    ]["jobId"] = "01K1DPA0000000000000000001"
    boolean_nested_agreement = copy.deepcopy(base)
    boolean_nested_agreement["authority"]["paymentPhaseInput"]["agreement"][
        "listingRef"
    ]["version"] = True
    wrong_rail_registry_authority = {
        **copy.deepcopy(base), "expectedRailRegistryAuthority": CLAIMS["buyer"]
    }
    wrong_rail_phase_handler = copy.deepcopy(base)
    substituted_rail = copy.deepcopy(
        wrong_rail_phase_handler["authority"]["railDefinition"]
    )
    substituted_rail["phaseHandler"] = "pay-x402"
    substituted_rail = ref.sign_embedded(
        {k: v for k, v in substituted_rail.items() if k != "signature"},
        CLAIMS["network"], SEEDS["network"], ref._RAIL_DOMAIN,
    )
    wrong_rail_phase_handler["authority"]["railDefinition"] = substituted_rail
    wrong_rail_phase_handler["authority"]["paymentPhaseInput"][
        "rail"
    ] = copy.deepcopy(substituted_rail)
    rekeyed_intent = copy.deepcopy(intent)
    rekeyed_commitment = rekeyed_intent["operations"][3]["payload"]["artifact"]
    rekeyed_commitment = ref.sign_embedded(
        {k: v for k, v in rekeyed_commitment.items() if k != "signature"},
        CLAIMS["buyer"], SEEDS["buyer"], ref._COMMITMENT_DOMAIN,
    )
    rekeyed_intent["operations"][3]["payload"]["artifact"] = rekeyed_commitment
    next(
        binding for binding in rekeyed_intent["roleRoster"]
        if binding["role"] == "orchestrator"
    )["signer"] = CLAIMS["buyer"]
    rekeyed_authorizations = authorizations(rekeyed_intent)
    for index, authorization in enumerate(rekeyed_authorizations):
        if authorization["role"] == "orchestrator":
            rekeyed_authorizations[index] = ref.sign_authorization(
                {k: v for k, v in authorization.items() if k != "value"},
                SEEDS["buyer"],
            )
    rekeyed_authority = authorization_authority(rekeyed_intent)
    attacker_session = atomic_payment_session_context(rekeyed_intent)
    next(
        party for party in attacker_session["parties"]
        if party["role"] == "orchestrator"
    )["primaryClaim"] = CLAIMS["buyer"]
    rekeyed_authority["atomicSessionContext"] = attacker_session
    rekeyed_authority["paymentPhaseInput"][
        "atomicSessionContext"
    ] = copy.deepcopy(attacker_session)
    rekeyed_authority["atomicSessionContextEvidence"] = encoded_evidence(
        "test-atomic-session-context",
        {
            "jobId": rekeyed_intent["jobId"],
            "contextHash": ref.sha256_hex(ref.jcs_bytes(attacker_session)),
            "proofProfile": "demos-bft-proof/test-1",
        },
        "buyer", ref._SESSION_CONTEXT_TEST_DOMAIN,
    )
    self_consistent_session_rekey = {
        "intent": rekeyed_intent,
        "authorizations": rekeyed_authorizations,
        "authority": rekeyed_authority,
        "publicKeys": PUBLIC_KEYS,
    }
    stale_session_source_evidence = copy.deepcopy(base)
    stale_source = stale_session_source_evidence["authority"][
        "sessionContextSource"
    ]
    stale_source["priorPhaseOutputs"]["attackerExtension"] = {
        "accepted": True,
    }
    stale_projection = atomic_payment_session_context_from_source(stale_source)
    stale_session_source_evidence["authority"][
        "atomicSessionContext"
    ] = stale_projection
    stale_session_source_evidence["authority"]["paymentPhaseInput"][
        "atomicSessionContext"
    ] = copy.deepcopy(stale_projection)
    stale_session_source_evidence["authority"][
        "atomicSessionContextEvidence"
    ] = encoded_evidence(
        "test-atomic-session-context",
        {
            "jobId": intent["jobId"],
            "contextHash": ref.sha256_hex(ref.jcs_bytes(stale_projection)),
            "proofProfile": "demos-bft-proof/test-1",
        },
        "orchestrator", ref._SESSION_CONTEXT_TEST_DOMAIN,
    )

    rail_accepted_after_session = copy.deepcopy(base)
    late_rail = copy.deepcopy(
        rail_accepted_after_session["authority"]["railDefinition"]
    )
    late_rail["governance"]["acceptedAt"] = (
        rail_accepted_after_session["authority"]["sessionContextSource"][
            "startedAt"
        ] + 1
    )
    late_rail = ref.sign_embedded(
        {k: v for k, v in late_rail.items() if k != "signature"},
        CLAIMS["network"], SEEDS["network"], ref._RAIL_DOMAIN,
    )
    late_index, late_index_receipt, late_rail_receipt = rail_registry_material(
        late_rail
    )
    rail_accepted_after_session["authority"].update({
        "railDefinition": late_rail,
        "railRegistryIndex": late_index,
        "railRegistryIndexReceipt": late_index_receipt,
        "railDefinitionReceipt": late_rail_receipt,
    })
    rail_accepted_after_session["authority"]["paymentPhaseInput"][
        "rail"
    ] = copy.deepcopy(late_rail)

    rail_v2_missing_supersedes = copy.deepcopy(base)
    v2_rail = copy.deepcopy(
        rail_v2_missing_supersedes["authority"]["railDefinition"]
    )
    v2_rail["railVersion"] = 2
    v2_rail = ref.sign_embedded(
        {k: v for k, v in v2_rail.items() if k != "signature"},
        CLAIMS["network"], SEEDS["network"], ref._RAIL_DOMAIN,
    )
    v2_index, v2_index_receipt, v2_rail_receipt = rail_registry_material(v2_rail)
    rail_v2_missing_supersedes["authority"].update({
        "railDefinition": v2_rail,
        "railRegistryIndex": v2_index,
        "railRegistryIndexReceipt": v2_index_receipt,
        "railDefinitionReceipt": v2_rail_receipt,
    })
    rail_v2_missing_supersedes["authority"]["paymentPhaseInput"][
        "rail"
    ] = copy.deepcopy(v2_rail)

    noncanonical_registry_address = copy.deepcopy(base)
    bad_index = noncanonical_registry_address["authority"]["railRegistryIndex"]
    bad_index["entries"][0]["versions"][0]["logicalAddress"] = (
        "dacs4:rail:attacker-selected:1"
    )
    noncanonical_registry_address["authority"][
        "railRegistryIndexReceipt"
    ] = registry_anchor_receipt(
        bad_index["logicalAddress"], bad_index,
        label="rail-index-address-substitution", nonce="202",
    )
    payee_bound_intent = purchase_intent(payee_bound=True)
    payee_bound_base = {
        "intent": payee_bound_intent,
        "authorizations": authorizations(payee_bound_intent),
        "authority": authorization_authority(payee_bound_intent),
        "publicKeys": PUBLIC_KEYS,
    }
    wrong_payee_domain_intent = purchase_intent(
        payee_bound=True, agreement_domain=ref._AGREEMENT_DOMAIN,
    )
    wrong_payee_domain = {
        "intent": wrong_payee_domain_intent,
        "authorizations": authorizations(wrong_payee_domain_intent),
        "authority": authorization_authority(wrong_payee_domain_intent),
        "publicKeys": PUBLIC_KEYS,
    }
    wrong_payout_intent = purchase_intent(
        payee_bound=True, payout_address="dem-attacker-destination",
    )
    wrong_payout = {
        "intent": wrong_payout_intent,
        "authorizations": authorizations(wrong_payout_intent),
        "authority": authorization_authority(wrong_payout_intent),
        "publicKeys": PUBLIC_KEYS,
    }
    missing_payout_intent = purchase_intent(
        payee_bound=True, payout_bindings=[],
    )
    missing_payout = {
        "intent": missing_payout_intent,
        "authorizations": authorizations(missing_payout_intent),
        "authority": authorization_authority(missing_payout_intent),
        "publicKeys": PUBLIC_KEYS,
    }
    optional_source_vet_ref = copy.deepcopy(base)
    for party in optional_source_vet_ref["authority"][
        "sessionContextSource"
    ]["parties"]:
        party.pop("vetRecordRef", None)
    rebind_session_source_evidence(optional_source_vet_ref["authority"])
    wrong_buyer_ref = vet_record_ref(
        intent["jobId"], "buyer",
        composite_verification_record(intent["jobId"], "buyer"),
    )
    wrong_buyer_ref["contentHash"] = "99" * 32
    wrong_vet_ref_intent = purchase_intent(
        vet_ref_overrides={"buyer": wrong_buyer_ref},
    )
    wrong_vet_ref = {
        "intent": wrong_vet_ref_intent,
        "authorizations": authorizations(wrong_vet_ref_intent),
        "authority": authorization_authority(wrong_vet_ref_intent),
        "publicKeys": PUBLIC_KEYS,
    }
    missing_agreement_vet_ref_intent = purchase_intent(
        omit_agreement_vet_refs={"buyer"},
    )
    missing_agreement_vet_ref = {
        "intent": missing_agreement_vet_ref_intent,
        "authorizations": authorizations(missing_agreement_vet_ref_intent),
        "authority": authorization_authority(missing_agreement_vet_ref_intent),
        "publicKeys": PUBLIC_KEYS,
    }
    extended_atomic_payer = copy.deepcopy(base)
    extended_atomic_payer["authority"]["paymentPhaseInput"]["payer"][
        "runtimeSigner"
    ] = "not-portable"
    # RFC 8032 \u00a75.1.7: a signature scalar s must be below the group order L.
    # The Listing signature's s is replaced by s + L, which an unreduced
    # verifier would still accept.
    unreduced_listing_signature = copy.deepcopy(base)
    listing_signature = unreduced_listing_signature["authority"]["listing"]["signature"]
    raw_signature = ref.b64u_decode(listing_signature["value"])
    unreduced_s = int.from_bytes(raw_signature[32:], "little") + ref._L
    listing_signature["value"] = ref.b64u(
        raw_signature[:32] + unreduced_s.to_bytes(32, "little")
    )
    non_nfc_authorizations = copy.deepcopy(auths)
    non_nfc_authorizations[0]["unknown"] = "e\u0301"
    non_nfc_authorizations[0] = sign_authorization_unchecked(
        non_nfc_authorizations[0], non_nfc_authorizations[0]["role"]
    )
    return [
        vector("aw-auth-complete-envelope", ["AW-30", "AW-31", "AW-32", "AW-33", "AW-34", "AW-35", "AW-36", "AW-38"], "authorization", base, "pass", "Each required role, including the independently authorized payer rather than a Vet signer, signs the unmodified full envelope for this exact Work and context."),
        vector("aw-auth-mutation-invalidates", ["AW-30", "AW-35"], "authorization", {**base, "authorizations": tampered}, "fail", "Mutating a signed envelope member invalidates both binding and signature."),
        vector("aw-auth-listing-signature-scalar-unreduced", ["AW-33"], "authorization", unreduced_listing_signature, "fail", "A Listing signature whose scalar is not reduced below the Ed25519 group order (s + L) is invalid under RFC 8032, so the pinned Listing cannot authenticate the seller authority the authorizations are matched against."),
        vector("aw-auth-operation-index-binding", ["AW-32"], "authorization", {**base, "authorizations": wrong_index}, "fail", "ID, index and kind must identify the same signed operation."),
        vector("aw-auth-work-replay", ["AW-31", "AW-36"], "authorization", {**base, "authorizations": other_work}, "fail", "Authorization cannot be replayed to another Work."),
        vector("aw-auth-required-role-missing", ["AW-34"], "authorization", {**base, "authorizations": missing}, "fail", "Every operation role needs its own authorization."),
        vector("aw-outer-submitter-is-not-role", ["AW-37"], "authorization", outer, "pass", "An unrelated outer sender does not alter signed DACS role authorization."),
        vector("aw-outer-submitter-cannot-fill-authorization", ["AW-34", "AW-37"], "authorization", outer_cannot_fill_missing, "fail", "Even when the outer submitter equals the missing role signer, it cannot replace that role's operation authorization."),
        vector("aw-payer-signer-mismatch", ["AW-33", "AW-38"], "authorization", {**base, "authorizations": wrong_signer}, "fail", "Vet/orchestrator authority does not become payer authority."),
        vector("aw-payer-role-relabel", ["AW-36", "AW-38"], "authorization", {**base, "authorizations": wrong_role}, "fail", "A signature for one role cannot be relabelled as payer."),
        vector("aw-auth-version-algorithm-bound", ["AW-30", "AW-35", "AW-36"], "authorization", {**base, "authorizations": bad_algorithm}, "fail", "Algorithm and version are signed envelope members."),
        vector("aw-auth-ecdsa-label-confusion", ["AW-30", "AW-35", "AW-36"], "authorization", {**base, "authorizations": ecdsa_relabel}, "fail", "A valid Ed25519 signature cannot be relabelled as ECDSA-secp256k1."),
        vector("aw-auth-sr1-label-confusion", ["AW-30", "AW-35", "AW-36"], "authorization", {**base, "authorizations": sr1_relabel}, "fail", "A valid Ed25519 signature cannot be relabelled as an sr1 aggregate."),
        vector("aw-auth-boolean-phase-index", ["AW-30", "AW-32"], "authorization", {**base, "authorizations": bool_phase_index}, "fail", "Schema validation rejects Boolean true before it can compare equal to integer phase 1."),
        vector("aw-auth-boolean-operation-index", ["AW-30", "AW-32"], "authorization", {**base, "authorizations": bool_operation_index}, "fail", "Schema validation rejects Boolean operation indexes before semantic indexing."),
        vector("aw-auth-signature-bytes-invalid", ["AW-30", "AW-35"], "authorization", {**base, "authorizations": bad_signature}, "fail", "A syntactically shaped but false signature is rejected cryptographically."),
        vector("aw-auth-signature-base64url-alias", ["AW-30", "AW-35"], "authorization", {**base, "authorizations": alias_signature}, "fail", "A non-canonical Base64URL alias of valid signature bytes is rejected."),
        vector("aw-auth-signature-wrong-length", ["AW-30", "AW-35"], "authorization", {**base, "authorizations": short_signature}, "fail", "An Ed25519 authorization signature must decode to exactly 64 bytes."),
        vector("aw-auth-public-key-wrong-length", ["AW-30", "AW-35"], "authorization", {**base, "publicKeys": short_public_keys}, "fail", "An Ed25519 public key must decode to exactly 32 bytes."),
        vector("aw-auth-capability-network-substitution", ["AW-20", "AW-30"], "authorization", {**base, "capability": wrong_network_capability}, "fail", "An authenticated capability for another network cannot authorize this Work."),
        vector("aw-auth-capability-execution-substitution", ["AW-19", "AW-20", "AW-30"], "authorization", {**base, "capability": wrong_execution_capability}, "fail", "An authenticated capability for another execution profile cannot authorize this Work."),
        vector("aw-auth-capability-profile-substitution", ["AW-20", "AW-30"], "authorization", {**base, "capability": wrong_profile_capability}, "fail", "The capability must admit the exact signed Work profile."),
        vector("aw-auth-capability-schema-substitution", ["AW-30", "AW-77"], "authorization", {**base, "capability": wrong_schema_capability}, "fail", "Authorization consumes the exact authenticated operation-kind and payload-schema map."),
        vector("aw-auth-capability-operation-kind-duplicate", ["AW-25", "AW-30", "AW-77"], "authorization", {**base, "capability": duplicate_kind_capability}, "fail", "Set-equivalent operation-kind lists with duplicates are not the exact canonical capability list."),
        vector("aw-auth-capability-proof-profile-substitution", ["AW-30", "AW-48"], "authorization", {**base, "capability": wrong_proof_capability}, "fail", "Authorization cannot adopt a proof profile merely because an attacker re-signed a capability."),
        vector("aw-auth-forged-self-consistent-roster", ["AW-33"], "authorization", {**base, "intent": forged_intent, "authorizations": forged_auths}, "fail", "A self-consistent roster and signature set cannot override authenticated agreement, bundle, and payer authority maps."),
        vector("aw-auth-role-authority-missing", ["AW-33"], "authorization", missing_authority, "indeterminate", "Missing independent agreement/bundle/payer authority cannot establish a roster role."),
        vector("aw-auth-cf3-parameter-identity", ["AW-30", "AW-33"], "authorization", {"intent": parameter_intent, "authorizations": parameter_auths, "authority": parameter_authority, "publicKeys": PUBLIC_KEYS}, "pass", "Canonical ClaimReference parameters remain in signed bytes but do not split CF-3 party authority or key resolution."),
        vector("aw-auth-sequential-anchor-nonce-missing", ["AW-33", "AW-48"], "authorization", missing_anchor_nonce, "fail", "The sequential-gate AnchorReceipt and its authenticated proof must both bind the applicable Demos writer nonce."),
        vector("aw-auth-payment-session-context-mismatch", ["AW-33"], "authorization", mismatched_payment_session, "fail", "AtomicPaymentPhaseInputV1 must carry the exact projection of the independently authenticated SessionContext source rather than an unrelated nested copy."),
        vector("aw-auth-payment-agreement-boolean-alias", ["AW-8", "AW-33"], "authorization", boolean_nested_agreement, "fail", "Byte-exact nested Agreement carriage rejects Python's true-equals-one structural alias."),
        vector("aw-auth-rail-registry-steward-mismatch", ["AW-33"], "authorization", wrong_rail_registry_authority, "fail", "A rail definition must verify under the independently pinned registry steward, not a caller-selected or capability-authority substitute."),
        vector("aw-auth-rail-phase-handler-mismatch", ["AW-33", "AW-77"], "authorization", wrong_rail_phase_handler, "fail", "A steward-signed RailDefinition must still satisfy the native-DEM RD-5/RD-6 shape and match the pinned pay-dem phase."),
        vector("aw-auth-self-consistent-session-orchestrator-rekey", ["AW-33"], "authorization", self_consistent_session_rekey, "fail", "Re-signing the commitment, roster, authorizations, and nested session evidence under a substituted orchestrator cannot replace the independently authenticated Atomic session projection."),
        vector("aw-auth-session-source-evidence-stale", ["AW-33"], "authorization", stale_session_source_evidence, "fail", "Recomputing and re-signing the Atomic projection cannot authorize a changed portable SessionContext source when its independent source evidence remains stale."),
        vector("aw-auth-rail-accepted-after-session", ["AW-33"], "authorization", rail_accepted_after_session, "fail", "A valid steward signature and fresh anchor receipts cannot move RailDefinition acceptance past the authenticated session start."),
        vector("aw-auth-rail-v2-supersedes-missing", ["AW-33"], "authorization", rail_v2_missing_supersedes, "fail", "A later RailDefinition version must name the prior version it supersedes before registry selection."),
        vector("aw-auth-rail-index-address-noncanonical", ["AW-33", "AW-74"], "authorization", noncanonical_registry_address, "fail", "A finalized registry index cannot redirect the selected rail to an address other than dacs4:rail:{CF-4(railId)}:{railVersion}."),
        vector("aw-auth-payee-bound-agreement", ["AW-33"], "authorization", payee_bound_base, "pass", "Atomic authorization accepts the distinct payee-bound agreement, commit phase, signature domain, exact payout coverage, and selected pay-dem destination as one authority chain."),
        vector("aw-auth-payee-bound-cross-domain-signature", ["AW-33", "AW-35"], "authorization", wrong_payee_domain, "fail", "A PayeeBoundAgreementDocument signed under the legacy dacs-agreement domain cannot authorize Atomic payment."),
        vector("aw-auth-payee-bound-destination-mismatch", ["AW-33"], "authorization", wrong_payout, "fail", "Atomic PB-1 requires the selected pay-dem rail, phase index, and runtime payee destination to equal the co-signed payout binding."),
        vector("aw-auth-payee-bound-payout-coverage-missing", ["AW-33"], "authorization", missing_payout, "fail", "A payee-bound agreement must cover every pinned pay phase exactly once before Atomic payment authorization."),
        vector("aw-auth-session-vet-ref-optional", ["AW-33"], "authorization", optional_source_vet_ref, "pass", "Portable SessionContext vetRecordRef is optional; when omitted, the signed Agreement AttestationRef still resolves the applicable Vet operation artifact."),
        vector("aw-auth-session-vet-ref-operation-mismatch", ["AW-33"], "authorization", wrong_vet_ref, "fail", "Matching signed Agreement and SessionContext AttestationRefs cannot claim a content hash different from the immutable Purchase Vet operation artifact."),
        vector("aw-auth-agreement-vet-ref-required", ["AW-33"], "authorization", missing_agreement_vet_ref, "fail", "Each buyer and seller AgreementParty requires a normative Vet AttestationRef even though the portable SessionParty copy is optional."),
        vector("aw-auth-atomic-payer-shape-closed", ["AW-7", "AW-33"], "authorization", extended_atomic_payer, "fail", "AtomicPaymentPhaseInputV1 closes its nested payer and payee records as well as its top-level record."),
        vector("aw-auth-unknown-string-not-nfc", ["AW-8", "AW-30", "AW-35"], "authorization", {**base, "authorizations": non_nfc_authorizations}, "fail", "A valid signature cannot make a preserved non-NFC authorization member conform to recursive CF-1."),
    ]


def execution_vectors() -> list[dict[str, Any]]:
    intent = purchase_intent()
    wid = ref.work_id(intent)
    canonical = ref.canonicalize(intent)
    tx_a = {"kind": "demos-transaction", "value": "tx-a"}
    tx_b = {"kind": "demos-transaction", "value": "tx-b"}
    included = ledger_evidence("attempt-a", wid, "included-committed", tx_a)
    nonincluded = ledger_evidence("attempt-a", wid, "authoritative-non-inclusion", tx_a)
    attempt_auths = authorizations(intent)
    attempt_a = {"attemptVersion": "1", "attemptClass": "normal", "workId": wid, "attemptId": "attempt-a", "canonicalWorkBytes": canonical, "authorizations": attempt_auths, "nativeTransactionRef": tx_a, "nonce": "attempt-nonce-a", "fee": "1", "lifecycleEvidence": included}
    attempt_b = {"attemptVersion": "1", "attemptClass": "normal", "workId": wid, "attemptId": "attempt-b", "canonicalWorkBytes": canonical, "authorizations": attempt_auths, "nativeTransactionRef": tx_b, "nonce": "attempt-nonce-b", "fee": "1"}
    attempt_a_non = {**attempt_a, "lifecycleEvidence": nonincluded}
    attempt_b_replacement = {
        **attempt_b, "attemptClass": "replacement", "replacementFor": "attempt-a",
    }
    wrong_native_evidence = ledger_evidence(
        "attempt-a", wid, "included-committed", tx_b
    )
    committed = final_receipt(intent)
    rolled = final_receipt(intent, "rolled-back", 4)
    receipt_wrong_proof_capability = mutate(
        capability(), ["proofProfile"], "attacker-proof/1"
    )
    receipt_wrong_proof_capability = sign_capability(receipt_wrong_proof_capability)
    receipt_wrong_schema_capability = mutate(
        capability(), ["payloadSchemas", "native-dem-transfer"],
        "https://attacker.invalid/native-transfer.json",
    )
    receipt_wrong_schema_capability = sign_capability(receipt_wrong_schema_capability)
    malformed_payload_intent = copy.deepcopy(intent)
    del malformed_payload_intent["operations"][5]["payload"]["amount"]
    malformed_payload_receipt = final_receipt(malformed_payload_intent)
    missing_storage_output = copy.deepcopy(committed)
    del missing_storage_output["operationResults"][3]["storageOutput"]
    missing_storage_output["operationResults"][3]["outputHash"] = ref.sha256_hex(
        ref.jcs_bytes(None)
    )
    missing_storage_output["operationReceiptRoot"] = ref.operation_receipt_root(
        missing_storage_output["operationResults"]
    )
    missing_storage_output = rebind_receipt_finality(missing_storage_output)
    wrong_slot_before_generation = mutate(
        committed, ["paymentSlot", "before", "generation"], 1
    )
    wrong_slot_before_generation = rebind_receipt_finality(
        wrong_slot_before_generation
    )
    wrong_slot_after_generation = mutate(
        committed, ["paymentSlot", "after", "generation"], 1
    )
    wrong_slot_after_generation = rebind_receipt_finality(
        wrong_slot_after_generation
    )
    wrong_slot_after_digest = mutate(
        committed, ["paymentSlot", "after", "conflictDigest"], "99" * 32
    )
    wrong_slot_after_digest = rebind_receipt_finality(wrong_slot_after_digest)
    invalid_root = mutate(committed, ["operationReceiptRoot"], "00" * 32)
    bad_input_hash = mutate(committed, ["operationResults", 0, "inputHash"], "00" * 32)
    bad_output_hash = mutate(committed, ["operationResults", 0, "outputHash"], "00" * 32)
    bad_effects_root = mutate(committed, ["businessState", "effectsRoot"], "00" * 32)
    partial = mutate(committed, ["operationResults", 2, "status"], "rolled-back")
    leaked = copy.deepcopy(rolled)
    leaked_witness = json.loads(ref.b64u_decode(
        leaked["businessState"]["evidence"]["value"]
    ).decode("utf-8"))
    leaked_witness["postState"]["payment-slot"] = {"state": "settled"}
    leaked_witness = ref.sign_embedded(
        {k: v for k, v in leaked_witness.items() if k != "signature"},
        CLAIMS["network"], SEEDS["network"], ref._STATE_TEST_DOMAIN,
    )
    leaked["businessState"]["evidence"]["value"] = ref.b64u(ref.jcs_bytes(leaked_witness))
    leaked["businessState"]["postRoot"] = ref.state_root(leaked_witness["postState"])
    missing_finality = copy.deepcopy(committed)
    del missing_finality["finalityEvidence"]
    bad_finality = copy.deepcopy(committed)
    bad_finality["finalityEvidence"] = encoded_evidence(
        "test-bft-checkpoint",
        {
            "kind": "test-bft-checkpoint",
            "networkId": committed["networkId"],
            "blockId": committed["blockRef"]["id"],
            "receiptCommitment": "00" * 32,
            "validatorSetId": "test-validator-set-1",
        },
        "network", ref._CHECKPOINT_TEST_DOMAIN,
    )
    wrong_slot_key = mutate(committed, ["paymentSlot", "key", "phaseIndex"], 1)
    completion_for_slot = completion_intent(committed)
    completion_receipt_for_slot = final_receipt(completion_for_slot)
    changed_completion_slot = mutate(
        completion_receipt_for_slot, ["paymentSlot", "after", "state"], "vacant"
    )
    mismatched_delivery_bytes_intent = mutate(
        completion_for_slot,
        ["operations", 1, "payload", "bytes"],
        ref.b64u(b"attacker-substituted-result"),
    )
    mismatched_delivery_bytes_receipt = final_receipt(
        mismatched_delivery_bytes_intent
    )
    storage_index = 3
    projection_fixture = projected_anchor_fixture(intent, committed, storage_index)
    projection = {
        "intent": intent, "receipt": committed,
        **projection_fixture, "publicKeys": PUBLIC_KEYS,
    }
    bad_projection = mutate(projection, ["anchorReceipt", "transactionRef", "value"], f"demos:{wid}")
    missing_anchor_finality = copy.deepcopy(projection)
    del missing_anchor_finality["anchorReceipt"]["finalityProfile"]
    mutated_anchor_nonce = mutate(
        projection, ["anchorReceipt", "nonce"], "attacker-nonce"
    )
    network_id_shortcut = copy.deepcopy(projection)
    del network_id_shortcut["anchorReceipt"]["substrate"]
    network_id_shortcut["anchorReceipt"]["networkId"] = committed["networkId"]
    bad_path = mutate(projection, ["operationEvidence", "inclusionPath", 0, "hash"], "00" * 32)
    cap = capability()
    limits_base = {"capability": cap, "intent": intent, "executionTimeMs": 100, "proofMaterial": {"proofVersion": "test-1", "value": "ok"}, "checkedBy": "node", "authoritativeSource": "consensus", "publicKeys": PUBLIC_KEYS, "priorAuthenticatedState": "in-flight", "laterObservation": "indeterminate", "retainedState": "in-flight"}
    byte_limit_intent = intent_with_canonical_size(intent, cap["limits"]["maxCanonicalBytes"])
    operation_limit_intent = intent_with_operation_count(intent, cap["limits"]["maxOperations"])
    byte_limit = {**limits_base, "intent": byte_limit_intent}
    operation_limit = {**limits_base, "intent": operation_limit_intent}
    time_limit = {**limits_base, "executionTimeMs": cap["limits"]["maxExecutionTimeMs"]}
    proof_limit = focused_proof_package_with_size(
        limits_base, cap["limits"]["maxProofBytes"]
    )
    proof_over_limit = focused_proof_package_with_size(
        limits_base, cap["limits"]["maxProofBytes"] + 1
    )
    limits_base = add_focused_limit_evidence(limits_base)
    byte_limit = add_focused_limit_evidence(byte_limit)
    operation_limit = add_focused_limit_evidence(operation_limit)
    time_limit = add_focused_limit_evidence(time_limit)
    odd_leaves = committed["operationResults"][:3]
    odd_root = ref.operation_receipt_root(odd_leaves)
    receipt_native_ref = copy.deepcopy(
        committed["winningAttempt"]["nativeTransactionRef"]
    )
    receipt_attempt = {
        **attempt_a,
        "nativeTransactionRef": receipt_native_ref,
        "lifecycleEvidence": ledger_evidence(
            "attempt-a", wid, "included-committed", receipt_native_ref
        ),
    }
    duplicate_native_ref_attempt = {
        **attempt_b, "nativeTransactionRef": copy.deepcopy(tx_a),
    }
    wrong_winner_receipt = copy.deepcopy(committed)
    wrong_winner_receipt["winningAttempt"]["attemptId"] = "attempt-attacker"
    wrong_winner_receipt = rebind_receipt_finality(wrong_winner_receipt)
    wrong_commit_fee = copy.deepcopy(committed)
    wrong_commit_fee["envelopeEffects"]["feeCharged"] = "2"
    wrong_commit_fee = rebind_receipt_finality(wrong_commit_fee)
    wrong_rollback_fee = copy.deepcopy(rolled)
    wrong_rollback_fee["envelopeEffects"] = {
        "nonceConsumed": False, "feeCharged": "0",
    }
    wrong_rollback_fee = rebind_receipt_finality(wrong_rollback_fee)
    wrong_slot_validator_receipt = copy.deepcopy(committed)
    wrong_slot_subject = json.loads(ref.b64u_decode(
        wrong_slot_validator_receipt["slotStateEvidence"]["value"]
    ).decode("utf-8"))
    wrong_slot_subject["validatorSetId"] = "attacker-validator-set"
    wrong_slot_subject = ref.sign_embedded(
        {k: v for k, v in wrong_slot_subject.items() if k != "signature"},
        CLAIMS["network"], SEEDS["network"], ref._SLOT_STATE_TEST_DOMAIN,
    )
    wrong_slot_validator_receipt["slotStateEvidence"]["value"] = ref.b64u(
        ref.jcs_bytes(wrong_slot_subject)
    )
    wrong_business_profile_receipt = copy.deepcopy(committed)
    wrong_business_subject = json.loads(ref.b64u_decode(
        wrong_business_profile_receipt["businessState"]["evidence"]["value"]
    ).decode("utf-8"))
    wrong_business_subject["proofProfile"] = "attacker-proof/1"
    wrong_business_subject = ref.sign_embedded(
        {k: v for k, v in wrong_business_subject.items() if k != "signature"},
        CLAIMS["network"], SEEDS["network"], ref._STATE_TEST_DOMAIN,
    )
    wrong_business_profile_receipt["businessState"]["evidence"][
        "value"
    ] = ref.b64u(ref.jcs_bytes(wrong_business_subject))
    exact_replay = {
        key: copy.deepcopy(value)
        for key, value in attempt_b.items()
        if key not in {"nonce", "lifecycleEvidence", "observation"}
    }
    exact_replay.update({
        "attemptClass": "replay", "fee": "0", "replayOf": "attempt-a",
        "returnedWinner": "attempt-a",
        "replayEffects": {"nonceConsumed": False, "feeCharged": "0"},
    })
    charged_replay = {
        **exact_replay, "fee": "1",
        "replayEffects": {"nonceConsumed": True, "feeCharged": "1"},
    }
    replay_with_nonce = {
        **exact_replay, "nonce": "candidate-replay-nonce",
    }
    unresolved_attempt = {
        key: copy.deepcopy(value)
        for key, value in attempt_a.items()
        if key != "lifecycleEvidence"
    }
    unresolved_attempt["observation"] = "not-found"
    missing_attempt_class = copy.deepcopy(attempt_a)
    del missing_attempt_class["attemptClass"]
    nonwinning_wrong_fee = {**attempt_b, "fee": "999999"}
    substituted_attempt_nonce = {
        **attempt_a, "nonce": "attacker-substituted-nonce"
    }
    mixed_replacement_replay = {
        **attempt_b_replacement, "replayOf": "attempt-a",
        "returnedWinner": "invented", "fee": "999",
        "replayEffects": {"nonceConsumed": True, "feeCharged": "999"},
    }
    rolled_back_winner_for_committed_receipt = {
        **receipt_attempt,
        "lifecycleEvidence": ledger_evidence(
            "attempt-a", wid, "included-rolled-back", receipt_native_ref
        ),
    }
    # Without a receipt, the inventory is bound to the block of the presented
    # authenticated lifecycle evidence; with none, no block binds it.
    stale_inventory_block = "block-899"
    assert stale_inventory_block != nonincluded["blockId"]
    stale_inventory = with_effect_inventory({"intent": intent, "attempts": [attempt_a_non, attempt_b_replacement], "winningAttemptId": None, "publicKeys": PUBLIC_KEYS}, [])
    stale_inventory["ledgerInventory"] = effect_inventory(
        wid, [], block_id=stale_inventory_block
    )
    unbound_inventory = with_effect_inventory({"intent": intent, "attempts": [unresolved_attempt], "winningAttemptId": None, "publicKeys": PUBLIC_KEYS}, [])
    wrong_attempt_proof_profile = copy.deepcopy(receipt_attempt)
    wrong_attempt_proof_profile["lifecycleEvidence"][
        "proofProfile"
    ] = "attacker-proof/1"
    wrong_attempt_proof_profile["lifecycleEvidence"] = resign_ledger_proof(
        wrong_attempt_proof_profile["lifecycleEvidence"]
    )
    extended_candidate_lifecycle = copy.deepcopy(receipt_attempt)
    extended_candidate_lifecycle["lifecycleEvidence"]["clientAction"] = "replace"
    extended_candidate_lifecycle["lifecycleEvidence"] = resign_ledger_proof(
        extended_candidate_lifecycle["lifecycleEvidence"]
    )
    return [
        vector("aw-attempt-byte-identity", ["AW-39", "AW-40"], "attempts", with_effect_inventory({"intent": intent, "attempts": [attempt_a], "winningAttemptId": "attempt-a", "authority": authorization_authority(intent), "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "pass", "Native attempt identity is distinct while Work bytes, authorizations, and workId remain immutable."),
        vector("aw-attempt-changed-bytes", ["AW-39"], "attempts", with_effect_inventory({"intent": intent, "attempts": [{**attempt_a, "canonicalWorkBytes": canonical + " "}], "winningAttemptId": "attempt-a", "authority": authorization_authority(intent), "publicKeys": PUBLIC_KEYS}, []), "fail", "Replacement cannot alter canonical Work bytes."),
        vector("aw-replacement-with-noninclusion", ["AW-41"], "attempts", with_effect_inventory({"intent": intent, "attempts": [attempt_a_non, attempt_b_replacement], "winningAttemptId": None, "publicKeys": PUBLIC_KEYS}, []), "pass", "Authenticated authoritative non-inclusion permits a replacement attempt under the replacement-authority rule."),
        vector("aw-replacement-effect-without-winner", ["AW-43", "AW-44"], "attempts", with_effect_inventory({"intent": intent, "attempts": [attempt_a_non, attempt_b_replacement], "winningAttemptId": None, "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "fail", "A Work-ledger inventory that records a business effect while the ledger selected no winning attempt shows an effect no winner fences."),
        vector("aw-effect-inventory-stale-without-receipt", ["AW-44"], "attempts", stale_inventory, "fail", "Without a receipt, an inventory taken at a block other than the presented authenticated lifecycle evidence's does not establish the Work's business effects."),
        vector("aw-effect-inventory-unbound-without-receipt", ["AW-44"], "attempts", unbound_inventory, "indeterminate", "Without a receipt or authenticated lifecycle evidence, no authenticated block binds the inventory, so the Work's business effects remain unavailable."),
        vector("aw-replacement-on-not-found", ["AW-41", "AW-42"], "attempts", with_effect_inventory({"intent": intent, "attempts": [unresolved_attempt, attempt_b_replacement], "winningAttemptId": None, "publicKeys": PUBLIC_KEYS}, []), "indeterminate", "Ordinary not-found remains on the indeterminate side of the replacement-authority boundary.", boundary_rules=["AW-42"]),
        vector("aw-single-ledger-winner", ["AW-43", "AW-44"], "attempts", with_effect_inventory({"intent": intent, "attempts": [attempt_a, attempt_b], "winningAttemptId": "attempt-a", "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "pass", "Exactly one included winner and business effect is the maximum valid cardinality.", boundary_rules=["AW-43", "AW-44"]),
        vector("aw-two-included-attempts", ["AW-43", "AW-44"], "attempts", with_effect_inventory({"intent": intent, "attempts": [attempt_a, {**attempt_b, "lifecycleEvidence": ledger_evidence("attempt-b", wid, "included-committed", tx_b)}], "winningAttemptId": "attempt-a", "publicKeys": PUBLIC_KEYS}, ["attempt-a", "attempt-b"]), "fail", "A second included winner/effect crosses the Work-ledger cardinality boundary.", boundary_rules=["AW-43", "AW-44"]),
        vector("aw-attempt-evidence-native-ref-mismatch", ["AW-40", "AW-59"], "attempts", with_effect_inventory({"intent": intent, "attempts": [{**attempt_a, "lifecycleEvidence": wrong_native_evidence}], "winningAttemptId": "attempt-a", "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "fail", "Signed lifecycle evidence for another native transaction cannot be attached to this attempt."),
        vector("aw-exact-replay-returns-winner", ["AW-45"], "attempts", with_effect_inventory({"intent": intent, "attempts": [attempt_a, exact_replay], "winningAttemptId": "attempt-a", "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "pass", "Exact replay returns the selected winner without execution or another fee/nonce effect."),
        vector("aw-attempt-class-required", ["AW-39", "AW-41", "AW-45"], "attempts", with_effect_inventory({"intent": intent, "attempts": [missing_attempt_class], "winningAttemptId": "attempt-a", "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "fail", "Every transport attempt declares exactly one normal, replacement, or replay class before class-specific fields are interpreted."),
        vector("aw-attempt-native-reference-duplicate", ["AW-39", "AW-40", "AW-43"], "attempts", with_effect_inventory({"intent": intent, "attempts": [attempt_a, duplicate_native_ref_attempt], "winningAttemptId": "attempt-a", "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "fail", "A second attempt ID naming the first canonical native reference crosses the one-to-one identity boundary.", boundary_rules=["AW-40"]),
        vector("aw-receipt-ledger-winner-bound", ["AW-43", "AW-46"], "attempts", with_effect_inventory({"intent": intent, "attempts": [receipt_attempt], "winningAttemptId": "attempt-a", "receipt": committed, "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "pass", "Receipt winner ID and native reference equal the authenticated ledger-selected attempt."),
        vector("aw-receipt-ledger-winner-mismatch", ["AW-43", "AW-46"], "attempts", with_effect_inventory({"intent": intent, "attempts": [receipt_attempt], "winningAttemptId": "attempt-a", "receipt": wrong_winner_receipt, "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "fail", "A separately finalized receipt cannot name another winning attempt."),
        vector("aw-exact-replay-additional-fee", ["AW-45", "AW-56", "AW-57"], "attempts", with_effect_inventory({"intent": intent, "attempts": [attempt_a, charged_replay], "winningAttemptId": "attempt-a", "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "fail", "An exact replay returns the old winner with zero additional fee and nonce effects."),
        vector("aw-exact-replay-candidate-nonce", ["AW-45", "AW-56", "AW-57"], "attempts", with_effect_inventory({"intent": intent, "attempts": [attempt_a, replay_with_nonce], "winningAttemptId": "attempt-a", "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "fail", "The generic replay arm permits profile-selected nonce policy, but this advertised candidate fee rule forbids a new replay nonce."),
        vector("aw-nonwinning-attempt-fee-rule", ["AW-39", "AW-56", "AW-57"], "attempts", with_effect_inventory({"intent": intent, "attempts": [attempt_a, nonwinning_wrong_fee], "winningAttemptId": "attempt-a", "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "fail", "The selected fee rule applies to every normal or replacement submission, not only the included winner."),
        vector("aw-attempt-authenticated-nonce-mismatch", ["AW-39", "AW-40", "AW-46", "AW-56"], "attempts", with_effect_inventory({"intent": intent, "attempts": [substituted_attempt_nonce], "winningAttemptId": "attempt-a", "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "fail", "The winning attempt nonce and fee must equal the subject authenticated by its ledger lifecycle evidence."),
        vector("aw-replacement-replay-class-confusion", ["AW-41", "AW-45", "AW-56"], "attempts", with_effect_inventory({"intent": intent, "attempts": [attempt_a_non, mixed_replacement_replay], "winningAttemptId": None, "publicKeys": PUBLIC_KEYS}, []), "fail", "An attempt cannot be classified simultaneously as a replacement and an exact replay, and replay requires an authenticated winner."),
        vector("aw-receipt-ledger-outcome-mismatch", ["AW-43", "AW-46"], "attempts", with_effect_inventory({"intent": intent, "attempts": [rolled_back_winner_for_committed_receipt], "winningAttemptId": "attempt-a", "receipt": committed, "publicKeys": PUBLIC_KEYS}, []), "fail", "A committed receipt cannot be paired with an authenticated included-rolled-back winner state."),
        vector("aw-rolled-back-winner-records-no-business-effect", ["AW-43", "AW-44", "AW-46"], "attempts", with_effect_inventory({"intent": intent, "attempts": [rolled_back_winner_for_committed_receipt], "winningAttemptId": "attempt-a", "receipt": rolled, "publicKeys": PUBLIC_KEYS}, []), "pass", "A rolled-back winner claims no committed payment or other business effect, so the Work-ledger inventory at its finalized receipt block lists no attempt."),
        vector("aw-rolled-back-winner-business-effect-recorded", ["AW-43", "AW-44", "AW-46"], "attempts", with_effect_inventory({"intent": intent, "attempts": [rolled_back_winner_for_committed_receipt], "winningAttemptId": "attempt-a", "receipt": rolled, "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "fail", "An inventory that records a business effect for a rolled-back winner contradicts its rolled-back receipt, which claims no committed payment or other business effect."),
        vector("aw-attempt-proof-profile-mismatch", ["AW-40", "AW-48"], "attempts", with_effect_inventory({"intent": intent, "attempts": [wrong_attempt_proof_profile], "winningAttemptId": "attempt-a", "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "fail", "Attempt lifecycle evidence binds the capability-selected proof profile and validator set."),
        vector("aw-attempt-candidate-lifecycle-shape", ["AW-40"], "attempts", with_effect_inventory({"intent": intent, "attempts": [extended_candidate_lifecycle], "winningAttemptId": "attempt-a", "publicKeys": PUBLIC_KEYS}, ["attempt-a"]), "fail", "The generic schema leaves lifecycle evidence to the selected profile; this candidate accepts only its complete closed synthetic witness shape."),
        vector("aw-receipt-complete-and-final", ["AW-46", "AW-47", "AW-48", "AW-49", "AW-50", "AW-51", "AW-52", "AW-57", "AW-60", "AW-64"], "receipt", {"intent": intent, "receipt": committed, "publicKeys": PUBLIC_KEYS}, "pass", "A reconstructible complete proof closure binds ordered operations and business state while its fee/nonce effects grant no second-payment authority.", boundary_rules=["AW-49", "AW-60", "AW-64"]),
        vector("aw-receipt-capability-proof-profile-substitution", ["AW-46", "AW-48"], "receipt", {"intent": intent, "receipt": committed, "capability": receipt_wrong_proof_capability, "publicKeys": PUBLIC_KEYS}, "fail", "Receipt verification uses the independently selected proof profile, not a substituted capability field."),
        vector("aw-receipt-capability-schema-substitution", ["AW-46", "AW-77"], "receipt", {"intent": intent, "receipt": committed, "capability": receipt_wrong_schema_capability, "publicKeys": PUBLIC_KEYS}, "fail", "Receipt verification consumes the exact authenticated payload-schema map."),
        vector("aw-receipt-slot-validator-set-mismatch", ["AW-46", "AW-48"], "receipt", {"intent": intent, "receipt": wrong_slot_validator_receipt, "publicKeys": PUBLIC_KEYS}, "fail", "The authenticated slot before/after proof binds the capability-selected validator set as well as its proof profile."),
        vector("aw-receipt-business-proof-profile-mismatch", ["AW-46", "AW-48"], "receipt", {"intent": intent, "receipt": wrong_business_profile_receipt, "publicKeys": PUBLIC_KEYS}, "fail", "Business-root evidence cannot replay across a different capability proof profile."),
        vector("aw-receipt-malformed-operation-payload", ["AW-46", "AW-77"], "receipt", {"intent": malformed_payload_intent, "receipt": malformed_payload_receipt, "publicKeys": PUBLIC_KEYS}, "fail", "A self-consistent receipt cannot bypass exact validation of the signed operation payload."),
        vector("aw-receipt-storage-output-missing", ["AW-46", "AW-51", "AW-65"], "receipt", {"intent": intent, "receipt": missing_storage_output, "publicKeys": PUBLIC_KEYS}, "fail", "A committed storage operation must carry its complete output binding before output hashing or projection."),
        vector("aw-receipt-slot-key-intent-mismatch", ["AW-46", "AW-74"], "receipt", {"intent": intent, "receipt": wrong_slot_key, "publicKeys": PUBLIC_KEYS}, "fail", "Receipt payment-slot key must exactly equal the signed intent tuple."),
        vector("aw-receipt-slot-before-generation-mismatch", ["AW-46", "AW-50"], "receipt", {"intent": intent, "receipt": wrong_slot_before_generation, "publicKeys": PUBLIC_KEYS}, "fail", "Purchase receipt slot before-state must equal the signed CAS expected state and generation."),
        vector("aw-receipt-slot-after-generation-mismatch", ["AW-46", "AW-50"], "receipt", {"intent": intent, "receipt": wrong_slot_after_generation, "publicKeys": PUBLIC_KEYS}, "fail", "Purchase receipt terminal generation must equal the signed CAS generation."),
        vector("aw-receipt-slot-after-digest-mismatch", ["AW-46", "AW-50"], "receipt", {"intent": intent, "receipt": wrong_slot_after_digest, "publicKeys": PUBLIC_KEYS}, "fail", "Purchase receipt terminal conflictDigest must equal the signed CAS payload."),
        vector("aw-completion-receipt-mutates-settled-slot", ["AW-46", "AW-50"], "receipt", {"intent": completion_for_slot, "receipt": changed_completion_slot, "purchaseIntent": intent, "purchaseReceipt": committed, "publicKeys": PUBLIC_KEYS}, "fail", "Completion must prove the settled slot is unchanged from before to after."),
        vector("aw-completion-storage-bytes-content-hash-mismatch", ["AW-46", "AW-51", "AW-77"], "receipt", {"intent": mismatched_delivery_bytes_intent, "receipt": mismatched_delivery_bytes_receipt, "purchaseIntent": intent, "purchaseReceipt": committed, "publicKeys": PUBLIC_KEYS}, "fail", "A self-consistent receipt cannot authenticate storage bytes whose signed contentHash names different decoded content."),
        vector("aw-receipt-root-mismatch", ["AW-46", "AW-51"], "receipt", {"intent": intent, "receipt": invalid_root, "publicKeys": PUBLIC_KEYS}, "fail", "Receipt result order/content is committed by the RFC 6962 root."),
        vector("aw-receipt-input-hash-mismatch", ["AW-46", "AW-51"], "receipt", {"intent": intent, "receipt": bad_input_hash, "publicKeys": PUBLIC_KEYS}, "fail", "Each operation receipt inputHash is recomputed from the exact signed operation payload."),
        vector("aw-receipt-synthetic-output-hash-mismatch", ["AW-46", "AW-51"], "receipt", {"intent": intent, "receipt": bad_output_hash, "publicKeys": PUBLIC_KEYS}, "fail", "The candidate test proof profile recomputes outputHash; its fixture formula is not a claim about production Demos bytes."),
        vector("aw-receipt-synthetic-effects-root-mismatch", ["AW-46", "AW-51"], "receipt", {"intent": intent, "receipt": bad_effects_root, "publicKeys": PUBLIC_KEYS}, "fail", "The candidate test proof profile recomputes effectsRoot over its disclosed pre/post fixture state."),
        vector("aw-operation-root-empty-primitive", ["AW-51"], "merkle", {"leaves": [], "claimedRoot": ref.operation_receipt_root([])}, "pass", "The empty RFC 6962-style primitive has its exact defined boundary root; Work intents themselves remain non-empty.", boundary=True),
        vector("aw-operation-root-odd-primitive", ["AW-51"], "merkle", {"leaves": odd_leaves, "claimedRoot": odd_root}, "pass", "An odd three-leaf tree uses the largest-power-of-two split without duplicating its last leaf.", boundary=True),
        vector("aw-committed-partial-status", ["AW-50", "AW-52"], "receipt", {"intent": intent, "receipt": partial, "publicKeys": PUBLIC_KEYS}, "fail", "A committed Work cannot report one rolled-back critical operation."),
        vector("aw-rollback-proves-unchanged", ["AW-53", "AW-54", "AW-55", "AW-56", "AW-58"], "receipt", {"intent": intent, "receipt": rolled, "publicKeys": PUBLIC_KEYS}, "pass", "The included rollback establishes this Work's failure and unchanged business state without claiming global attempt absence.", boundary_rules=["AW-58"]),
        vector("aw-committed-receipt-fee-rule-mismatch", ["AW-46", "AW-56"], "receipt", {"intent": intent, "receipt": wrong_commit_fee, "publicKeys": PUBLIC_KEYS}, "fail", "Committed receipt envelope effects must satisfy the authenticated fee rule."),
        vector("aw-rollback-receipt-fee-rule-mismatch", ["AW-53", "AW-56"], "receipt", {"intent": intent, "receipt": wrong_rollback_fee, "publicKeys": PUBLIC_KEYS}, "fail", "Rollback preserves business state but still reports the authenticated native fee and nonce effects."),
        vector("aw-rollback-state-leak", ["AW-54", "AW-55"], "receipt", {"intent": intent, "receipt": leaked, "publicKeys": PUBLIC_KEYS}, "fail", "A rollback witness exposing a payment-slot effect is rejected."),
        vector("aw-nonce-does-not-authorize-payment", ["AW-56", "AW-57"], "receipt", {"intent": intent, "receipt": rolled, "authorizesResubmission": True, "publicKeys": PUBLIC_KEYS}, "fail", "Persistent envelope effects do not authorize a second payment."),
        vector("aw-rollback-not-global-absence", ["AW-58"], "receipt", {"intent": intent, "receipt": rolled, "claimsOtherAttemptAbsent": True, "publicKeys": PUBLIC_KEYS}, "fail", "Claiming global absence crosses the semantic boundary of what an included rollback proves.", boundary=True),
        vector("aw-lifecycle-noninclusion-proof", ["AW-59"], "lifecycle", {"attemptId": "attempt-a", "nativeTransactionRef": tx_a, "expectedNonce": "attempt-nonce-a", "expectedFee": "1", "claimedState": "authoritative-non-inclusion", "evidence": nonincluded, "publicKeys": PUBLIC_KEYS}, "pass", "Authenticated lifecycle evidence, not a client observation, establishes non-inclusion."),
        vector("aw-lifecycle-native-ref-mismatch", ["AW-59", "AW-60"], "lifecycle", {"attemptId": "attempt-a", "nativeTransactionRef": tx_a, "expectedNonce": "attempt-nonce-a", "expectedFee": "1", "claimedState": "included-committed", "evidence": wrong_native_evidence, "publicKeys": PUBLIC_KEYS}, "fail", "Lifecycle evidence must bind the exact native transaction reference being queried."),
        vector("aw-lifecycle-missing-proof", ["AW-59", "AW-60"], "lifecycle", {"attemptId": "attempt-a", "nativeTransactionRef": tx_a, "expectedNonce": "attempt-nonce-a", "expectedFee": "1", "claimedState": "authoritative-non-inclusion", "publicKeys": PUBLIC_KEYS}, "indeterminate", "Missing non-inclusion evidence occupies the indeterminate proof-availability boundary.", boundary_rules=["AW-60"]),
        vector("aw-finality-proof-contradicted", ["AW-47", "AW-48", "AW-60"], "receipt", {"intent": intent, "receipt": bad_finality, "publicKeys": PUBLIC_KEYS}, "fail", "Contradictory proof material crosses the proof-status boundary into rejection.", boundary_rules=["AW-60"]),
        vector("aw-finality-proof-missing", ["AW-47", "AW-48", "AW-60"], "receipt", {"intent": intent, "receipt": missing_finality, "publicKeys": PUBLIC_KEYS}, "fail", "A receipt missing schema-required finality evidence is rejected before semantic verification."),
        vector("aw-crash-before-admission", ["AW-61"], "recovery", {"crashBoundary": "before-durable-admission", "inferredAbsent": False}, "pass", "At the pre-admission crash boundary, reconciliation does not infer absence.", boundary=True),
        vector("aw-crash-before-admission-infers-absence", ["AW-61"], "recovery", {"crashBoundary": "before-durable-admission", "inferredAbsent": True}, "fail", "A crash before durable admission cannot cross the evidence boundary into inferred absence.", boundary=True),
        vector("aw-crash-overlay-rollback", ["AW-62"], "recovery", {"crashBoundary": "during-overlay", "preState": {"slot": "vacant"}, "postRecoveryState": {"slot": "vacant"}}, "pass", "At the overlay crash boundary, recovery preserves the exact pre-state.", boundary=True),
        vector("aw-crash-overlay-state-leak", ["AW-62"], "recovery", {"crashBoundary": "during-overlay", "preState": {"slot": "vacant"}, "postRecoveryState": {"slot": "settled"}}, "fail", "A business-state change across the overlay crash boundary is rejected.", boundary=True),
        vector("aw-crash-after-commit-recovery", ["AW-63"], "recovery", {"crashBoundary": "after-consensus-commit", "committedReceiptHash": ref.receipt_hash(committed), "recoveredReceiptHash": ref.receipt_hash(committed), "committedWinner": "attempt-a", "recoveredWinner": "attempt-a"}, "pass", "At the post-commit crash boundary, recovery reproduces the same receipt and winner.", boundary=True),
        vector("aw-crash-after-commit-divergence", ["AW-63"], "recovery", {"crashBoundary": "after-consensus-commit", "committedReceiptHash": ref.receipt_hash(committed), "recoveredReceiptHash": "00" * 32, "committedWinner": "attempt-a", "recoveredWinner": "attempt-b"}, "fail", "A changed receipt or winner after the consensus-commit boundary is rejected.", boundary=True),
        vector("aw-receipt-service-unavailable", ["AW-49", "AW-64"], "receipt", {"intent": intent, "receipt": committed, "receiptAvailability": "unavailable", "publicKeys": PUBLIC_KEYS}, "indeterminate", "Receipt-service unavailability remains on the indeterminate side of the reconstruction boundary.", boundary_rules=["AW-49", "AW-64"]),
        vector("aw-anchor-projection", ["AW-65", "AW-66", "AW-67", "AW-68", "AW-69", "AW-70"], "projection", projection, "pass", "Storage result projects from independently verifiable receipt and inclusion path."),
        vector("aw-anchor-no-txhash-reinterpretation", ["AW-67", "AW-68"], "projection", bad_projection, "fail", "The operation reference is versioned and not demos:{txHash}."),
        vector("aw-anchor-finality-field-missing", ["AW-65", "AW-66"], "projection", missing_anchor_finality, "fail", "The projection must emit the complete finalized CORE AnchorReceipt shape."),
        vector("aw-anchor-nonce-mutated", ["AW-65", "AW-66"], "projection", mutated_anchor_nonce, "fail", "The projected AnchorReceipt nonce must copy the verified storage output exactly."),
        vector("aw-anchor-networkid-shortcut-rejected", ["AW-66"], "projection", network_id_shortcut, "fail", "A non-normative networkId member cannot substitute for CORE AnchorReceipt substrate."),
        vector("aw-anchor-inclusion-proof-invalid", ["AW-69", "AW-70"], "projection", bad_path, "fail", "A detached leaf is not evidence without a valid inclusion path."),
        vector("aw-node-limits-and-state-preservation", ["AW-71", "AW-72", "AW-73", "AW-75"], "limits", limits_base, "pass", "Node-enforced authenticated limits and consensus state survive a later indeterminate observation."),
        vector("aw-canonical-byte-limit-equality", ["AW-71"], "limits", byte_limit, "pass", "A Work whose JCS encoding equals maxCanonicalBytes is at the inclusive admission boundary.", boundary=True),
        vector("aw-operation-count-limit-equality", ["AW-71"], "limits", operation_limit, "pass", "A Work with exactly maxOperations operations is at the inclusive admission boundary.", boundary=True),
        vector("aw-execution-time-limit-equality", ["AW-71"], "limits", time_limit, "pass", "An execution at exactly maxExecutionTimeMs is at the inclusive node limit.", boundary=True),
        vector("aw-proof-byte-limit-equality", ["AW-71"], "limits", proof_limit, "pass", "The canonical proof measurement preimage exactly equal to maxProofBytes is admitted.", boundary=True),
        vector("aw-proof-byte-limit-one-over", ["AW-71"], "limits", proof_over_limit, "fail", "A proof-profile reservation one byte over maxProofBytes is rejected before execution.", boundary=True),
        vector("aw-client-only-limit-check", ["AW-71", "AW-72", "AW-73"], "limits", {**limits_base, "checkedBy": "client", "authoritativeSource": "client"}, "fail", "Client status and limit checks cannot replace node enforcement."),
        vector("aw-structured-proof-identity", ["AW-74"], "slot-distinction", {"leftKey": {"networkId": "a:b", "railId": "c", "jobId": "01K1DPA0000000000000000000", "phaseIndex": 0}, "rightKey": {"networkId": "a", "railId": "b:c", "jobId": "01K1DPA0000000000000000000", "phaseIndex": 0}, "displayKeyLeft": "a:b:c:01K1DPA0000000000000000000:0", "displayKeyRight": "a:b:c:01K1DPA0000000000000000000:0", "treatedAsSame": False}, "pass", "Structured typed components remain distinct at the display-collision boundary.", boundary=True),
        vector("aw-indeterminate-overwrites-auth-state", ["AW-75"], "limits", {**limits_base, "retainedState": "vacant"}, "fail", "Crossing from authenticated in-flight state to an indeterminate observation cannot erase the established state.", boundary=True),
    ]


def purchase_completion_vectors() -> list[dict[str, Any]]:
    purchase = purchase_intent(current_profile=True)
    purchase_receipt = final_receipt(purchase)
    completion = completion_intent(purchase_receipt)
    purchase_base = {
        "intent": purchase, "publicKeys": PUBLIC_KEYS,
        "listing": listing_fixture(purchase["jobId"], current_profile=True),
        "authenticatedOrchestrator": CLAIMS["orchestrator"],
        "atomicReceipt": purchase_receipt,
    }
    bad_vet = mutate(
        purchase, ["operations", 0, "payload", "artifact", "overallDecision"],
        "fail",
    )
    wrong_vet_address = mutate(
        purchase, ["operations", 0, "payload", "logicalAddress"],
        f"dacs2:composite:{purchase['jobId']}:did:dacs:test:buyer",
    )
    vet_cas = mutate(
        purchase, ["operations", 1, "payload", "writeCondition"],
        {"kind": "compare-and-set", "expectedContentHash": "00" * 32},
    )
    live_vet = mutate(purchase, ["operations", 0, "payload", "liveAction"], {"url": "https://vet.invalid"})
    bad_order = copy.deepcopy(purchase)
    bad_order["operations"][4], bad_order["operations"][5] = bad_order["operations"][5], bad_order["operations"][4]
    bad_commit = mutate(purchase, ["operations", 3, "payload", "artifact", "agreementHash"], "00" * 32)
    commitment_cas = mutate(
        purchase, ["operations", 3, "payload", "writeCondition"],
        {"kind": "compare-and-set", "expectedContentHash": "00" * 32},
    )
    agreement = purchase["operations"][2]["payload"]["artifact"]
    other_job_commitment = finality_commitment(
        "01K1DPA0000000000000000001", agreement
    )
    other_job_commitment_intent = mutate(
        purchase, ["operations", 3, "payload", "artifact"], other_job_commitment
    )
    wrong_listing_commitment = copy.deepcopy(
        purchase["operations"][3]["payload"]["artifact"]
    )
    wrong_listing_commitment["listingRef"]["contentHash"] = "99" * 32
    wrong_listing_commitment = ref.sign_embedded(
        {
            key: copy.deepcopy(value)
            for key, value in wrong_listing_commitment.items()
            if key != "signature"
        },
        CLAIMS["orchestrator"], SEEDS["orchestrator"], ref._COMMITMENT_DOMAIN,
    )
    wrong_listing_commitment_intent = mutate(
        purchase, ["operations", 3, "payload", "artifact"],
        wrong_listing_commitment,
    )
    mixed_receipt = mutate(purchase_receipt, ["operationResults", 2, "status"], "rolled-back")
    mixed_receipt["operationReceiptRoot"] = ref.operation_receipt_root(mixed_receipt["operationResults"])
    mixed_receipt = rebind_receipt_finality(mixed_receipt)
    mixed_status = {**purchase_base, "atomicReceipt": mixed_receipt}
    deadline = agreement["terms"]["deadline"]
    last_valid_receipt = final_receipt(purchase, block_timestamp=deadline - 1)
    deadline_equality_receipt = final_receipt(purchase, block_timestamp=deadline)
    last_valid_deadline = {**purchase_base, "atomicReceipt": last_valid_receipt}
    outside_deadline = {**purchase_base, "atomicReceipt": deadline_equality_receipt}
    client_time = {
        **purchase_base, "atomicReceipt": deadline_equality_receipt,
        "clientObservedAt": 1_800_000_030_000,
    }
    no_bft = dict(purchase_base)
    del no_bft["atomicReceipt"]
    purchase_commitment_projection = projected_anchor_fixture(
        purchase, purchase_receipt, 3
    )
    completion_base = {"intent": completion, "purchaseIntent": purchase, "purchaseCommitmentProjection": purchase_commitment_projection, "listing": listing_fixture(purchase["jobId"], current_profile=True), "authenticatedOrchestrator": CLAIMS["orchestrator"], "publicKeys": PUBLIC_KEYS, "claimsEvidenceFinalized": False, "claimsBundleFinalized": False}
    missing_commitment_projection = copy.deepcopy(completion_base)
    del missing_commitment_projection["purchaseCommitmentProjection"]
    bad_commitment_projection = mutate(
        completion_base,
        ["purchaseCommitmentProjection", "anchorReceipt", "contentHash"],
        "00" * 32,
    )
    bad_delivery = mutate(completion, ["operations", 1, "payload", "contentHash"], "00" * 32)
    wrong_delivery_address = mutate(
        completion, ["operations", 1, "payload", "logicalAddress"],
        f"dacs4:deliverable:01K1DPA0000000000000000001",
    )
    delivery_cas = mutate(
        completion, ["operations", 1, "payload", "writeCondition"],
        {"kind": "compare-and-set", "expectedContentHash": "00" * 32},
    )
    wrong_purchase_listing = mutate(
        purchase_base["listing"], ["pipeline", purchase["phaseIndex"], "kind"], "pay-x402"
    )
    wrong_purchase_phase = {**purchase_base, "listing": resign_listing(wrong_purchase_listing)}
    wrong_completion_listing = copy.deepcopy(completion_base["listing"])
    wrong_completion_listing["pipeline"].insert(
        completion["phaseIndex"], {"kind": "rate-counterparty"}
    )
    wrong_completion_phase = {
        **completion_base, "listing": resign_listing(wrong_completion_listing)
    }
    composed_purchase = composed_purchase_admission(purchase, purchase_receipt)
    sequential_purchase = purchase_intent(
        gate_mode="sequential", current_profile=True
    )
    sequential_purchase_receipt = final_receipt(sequential_purchase)
    composed_sequential_purchase = composed_purchase_admission(
        sequential_purchase, sequential_purchase_receipt
    )
    mismatched_gate_copy = copy.deepcopy(composed_purchase)
    mismatched_gate_copy["authority"]["gateMode"] = "sequential"
    alternate_seller_purchase = purchase_intent(
        seller_role="alternate-seller", current_profile=True
    )
    alternate_seller_receipt = final_receipt(alternate_seller_purchase)
    alternate_seller_admission = composed_purchase_admission(
        alternate_seller_purchase, alternate_seller_receipt
    )
    alternate_seller_admission["publicKeys"] = {
        **PUBLIC_KEYS,
        CLAIMS["alternate-seller"]: ALTERNATE_SELLER_PUBLIC_KEY,
    }
    composed_completion = composed_completion_admission(
        purchase, purchase_receipt, completion, final_receipt(completion)
    )
    composed_completion_both_claims = {
        **composed_completion,
        "claimsEvidenceFinalized": True,
        "claimsBundleFinalized": True,
    }
    mismatched_completion = completion_intent(
        purchase_receipt, gate_mode="sequential"
    )
    mismatched_completion_admission = composed_completion_admission(
        purchase, purchase_receipt, mismatched_completion,
        final_receipt(mismatched_completion),
    )
    failed_purchase = purchase_intent(current_profile=True)
    failed_purchase_receipt = final_receipt(
        failed_purchase, "rolled-back", 4
    )
    retry_purchase = purchase_intent(
        generation=failed_purchase_receipt["paymentSlot"]["after"]["generation"],
        expected_state="rolled-back",
        prior_failure=failed_purchase_receipt["receiptCommitment"],
        current_profile=True,
    )
    retry_receipt = final_receipt(
        retry_purchase,
        prior_slot_state=failed_purchase_receipt["paymentSlot"]["after"],
    )
    composed_retry = composed_purchase_admission(
        retry_purchase, retry_receipt,
        failure_intent=failed_purchase,
        failure_receipt=failed_purchase_receipt,
    )
    composed_retry_generation_skip = copy.deepcopy(composed_retry)
    composed_retry_generation_skip["slotAdmission"]["newState"][
        "generation"
    ] += 1
    # AWS-4: the composed slot transition is derived from the signed CAS.
    derived_claim = copy.deepcopy(composed_purchase)
    del derived_claim["slotAdmission"]["action"]
    derived_claim = add_composed_limit_evidence(derived_claim)
    derived_retry = copy.deepcopy(composed_retry)
    del derived_retry["slotAdmission"]["action"]
    derived_retry = add_composed_limit_evidence(derived_retry)
    observation_only = copy.deepcopy(composed_purchase)
    observation_only["slotAdmission"]["action"] = "observe"
    observation_only = add_composed_limit_evidence(observation_only)
    committed_observation = copy.deepcopy(observation_only)
    committed_observation["slotAdmission"]["attemptObservation"] = "committed"
    committed_observation = add_composed_limit_evidence(committed_observation)
    mismatched_transition = copy.deepcopy(composed_purchase)
    mismatched_transition["slotAdmission"]["action"] = "retry"
    mismatched_transition = add_composed_limit_evidence(mismatched_transition)
    # AW-44/AWS-14: business effects are taken from the Work-ledger inventory.
    purchase_wid = ref.work_id(purchase)
    purchase_winner = (
        purchase_receipt["winningAttempt"]["attemptId"],
        purchase_receipt["winningAttempt"]["nativeTransactionRef"],
    )
    inventory_missing = copy.deepcopy(composed_purchase)
    del inventory_missing["ledgerInventory"]
    inventory_missing = add_composed_limit_evidence(inventory_missing)
    inventory_empty = copy.deepcopy(composed_purchase)
    inventory_empty["ledgerInventory"] = effect_inventory(
        purchase_wid, [], block_id=purchase_receipt["blockRef"]["id"],
    )
    inventory_empty = add_composed_limit_evidence(inventory_empty)
    inventory_late_effect = copy.deepcopy(composed_purchase)
    inventory_late_effect["ledgerInventory"] = effect_inventory(
        purchase_wid,
        [
            purchase_winner,
            ("attempt-late", {"kind": "demos-transaction", "value": "tx-late-attempt"}),
        ],
        block_id=purchase_receipt["blockRef"]["id"],
    )
    inventory_late_effect = add_composed_limit_evidence(inventory_late_effect)
    inventory_other_attempt = copy.deepcopy(composed_purchase)
    inventory_other_attempt["ledgerInventory"] = effect_inventory(
        purchase_wid,
        [("attempt-ledger-other", purchase_winner[1])],
        block_id=purchase_receipt["blockRef"]["id"],
    )
    inventory_other_attempt = add_composed_limit_evidence(inventory_other_attempt)
    inventory_winner_other_ref = copy.deepcopy(composed_purchase)
    inventory_winner_other_ref["ledgerInventory"] = effect_inventory(
        purchase_wid,
        [(
            purchase_winner[0],
            {"kind": "demos-transaction", "value": "tx-ledger-other"},
        )],
        block_id=purchase_receipt["blockRef"]["id"],
    )
    inventory_winner_other_ref = add_composed_limit_evidence(
        inventory_winner_other_ref
    )
    unauthenticated_effects = copy.deepcopy(composed_purchase)
    del unauthenticated_effects["ledgerInventory"]
    unauthenticated_effects["businessEffectAttempts"] = [purchase_winner[0]]
    unauthenticated_effects = add_composed_limit_evidence(unauthenticated_effects)
    unauthenticated_effects_late = copy.deepcopy(inventory_late_effect)
    unauthenticated_effects_late["businessEffectAttempts"] = [purchase_winner[0]]
    unauthenticated_effects_late = add_composed_limit_evidence(
        unauthenticated_effects_late
    )
    caller_empty_effects = copy.deepcopy(composed_purchase)
    caller_empty_effects["businessEffectAttempts"] = []
    caller_empty_effects = add_composed_limit_evidence(caller_empty_effects)
    other_block = "block-atomic-902"
    assert other_block != purchase_receipt["blockRef"]["id"]
    inventory_other_block = copy.deepcopy(composed_purchase)
    inventory_other_block["ledgerInventory"] = effect_inventory(
        purchase_wid, [purchase_winner], block_id=other_block,
    )
    inventory_other_block = add_composed_limit_evidence(inventory_other_block)
    # The inventory must be authenticated by the network and bound to this
    # Work, proof profile, and validator set; each case changes one of these.
    inventory_body = {
        key: value for key, value in composed_purchase["ledgerInventory"].items()
        if key != "signature"
    }
    inventory_participant_signed = copy.deepcopy(composed_purchase)
    inventory_participant_signed["ledgerInventory"] = ref.sign_embedded(
        inventory_body, CLAIMS["payer"], SEEDS["payer"],
        ref._LEDGER_INVENTORY_TEST_DOMAIN,
    )
    inventory_participant_signed = add_composed_limit_evidence(
        inventory_participant_signed
    )
    inventory_signature_invalid = copy.deepcopy(composed_purchase)
    stripped_inventory = copy.deepcopy(inventory_late_effect["ledgerInventory"])
    stripped_inventory["effectAttempts"] = stripped_inventory["effectAttempts"][:1]
    assert {
        key: value for key, value in stripped_inventory.items() if key != "signature"
    } == inventory_body
    inventory_signature_invalid["ledgerInventory"] = stripped_inventory
    inventory_signature_invalid = add_composed_limit_evidence(
        inventory_signature_invalid
    )
    inventory_unsigned = copy.deepcopy(composed_purchase)
    inventory_unsigned["ledgerInventory"] = copy.deepcopy(inventory_body)
    inventory_unsigned = add_composed_limit_evidence(inventory_unsigned)
    other_work_id = ref.work_id(completion)
    assert other_work_id != purchase_wid
    inventory_other_work = copy.deepcopy(composed_purchase)
    inventory_other_work["ledgerInventory"] = effect_inventory(
        other_work_id, [purchase_winner], block_id=purchase_receipt["blockRef"]["id"],
    )
    inventory_other_work = add_composed_limit_evidence(inventory_other_work)
    inventory_other_proof_profile = copy.deepcopy(composed_purchase)
    inventory_other_proof_profile["ledgerInventory"] = effect_inventory(
        purchase_wid, [purchase_winner], block_id=purchase_receipt["blockRef"]["id"],
        proof_profile="demos-bft-proof/test-0",
    )
    inventory_other_proof_profile = add_composed_limit_evidence(
        inventory_other_proof_profile
    )
    inventory_other_validator_set = copy.deepcopy(composed_purchase)
    inventory_other_validator_set["ledgerInventory"] = effect_inventory(
        purchase_wid, [purchase_winner], block_id=purchase_receipt["blockRef"]["id"],
        validator_set_id="test-validator-set-0",
    )
    inventory_other_validator_set = add_composed_limit_evidence(
        inventory_other_validator_set
    )
    inventory_repeated_winner = copy.deepcopy(composed_purchase)
    inventory_repeated_winner["ledgerInventory"] = effect_inventory(
        purchase_wid, [purchase_winner, purchase_winner],
        block_id=purchase_receipt["blockRef"]["id"],
    )
    inventory_repeated_winner = add_composed_limit_evidence(inventory_repeated_winner)
    # The inventory and each entry have closed shapes; each case adds one
    # member and is re-signed by the network, so only the shape check fails.
    inventory_unknown_member = copy.deepcopy(composed_purchase)
    inventory_unknown_member["ledgerInventory"] = ref.sign_embedded(
        {**inventory_body, "note": "unrecognized member"},
        CLAIMS["network"], SEEDS["network"], ref._LEDGER_INVENTORY_TEST_DOMAIN,
    )
    inventory_unknown_member = add_composed_limit_evidence(inventory_unknown_member)
    entry_unknown_member_body = copy.deepcopy(inventory_body)
    assert [
        (entry["attemptId"], entry["nativeTransactionRef"])
        for entry in entry_unknown_member_body["effectAttempts"]
    ] == [purchase_winner]
    entry_unknown_member_body["effectAttempts"][0]["note"] = "unrecognized member"
    inventory_entry_unknown_member = copy.deepcopy(composed_purchase)
    inventory_entry_unknown_member["ledgerInventory"] = ref.sign_embedded(
        entry_unknown_member_body,
        CLAIMS["network"], SEEDS["network"], ref._LEDGER_INVENTORY_TEST_DOMAIN,
    )
    inventory_entry_unknown_member = add_composed_limit_evidence(
        inventory_entry_unknown_member
    )
    inventory_version_unsupported = copy.deepcopy(composed_purchase)
    inventory_version_unsupported["ledgerInventory"] = ref.sign_embedded(
        {**inventory_body, "inventoryVersion": "test-2"},
        CLAIMS["network"], SEEDS["network"], ref._LEDGER_INVENTORY_TEST_DOMAIN,
    )
    inventory_version_unsupported = add_composed_limit_evidence(
        inventory_version_unsupported
    )
    # Completion admission consumes the same Work-ledger inventory.
    completion_receipt = composed_completion["receipt"]
    completion_inventory_late_effect = copy.deepcopy(composed_completion)
    completion_inventory_late_effect["ledgerInventory"] = effect_inventory(
        ref.work_id(completion),
        [
            (
                completion_receipt["winningAttempt"]["attemptId"],
                completion_receipt["winningAttempt"]["nativeTransactionRef"],
            ),
            ("attempt-late", {"kind": "demos-transaction", "value": "tx-late-attempt"}),
        ],
        block_id=completion_receipt["blockRef"]["id"],
    )
    completion_inventory_late_effect = add_composed_limit_evidence(
        completion_inventory_late_effect
    )
    # A derived retry is decided by the authenticated prior slot state alone: a
    # held (in-flight) slot contradicts the signed rolled-back expectation
    # whatever local attempt observation a caller adds.
    retry_from_held_slot = copy.deepcopy(composed_retry)
    held_state = {
        key: value
        for key, value in retry_from_held_slot["slotAdmission"]["ledgerProof"]["state"].items()
        if key != "failureReceiptCommitment"
    }
    held_state["state"] = "in-flight"
    retry_from_held_slot["slotAdmission"]["ledgerProof"]["state"] = held_state
    retry_from_held_slot["slotAdmission"]["ledgerProof"] = resign_ledger_proof(
        retry_from_held_slot["slotAdmission"]["ledgerProof"]
    )
    retry_from_held_slot["slotAdmission"]["attemptObservation"] = "indeterminate"
    retry_from_held_slot["receipt"]["paymentSlot"]["before"] = copy.deepcopy(held_state)
    retry_from_held_slot["receipt"] = rebind_receipt_finality(
        retry_from_held_slot["receipt"]
    )
    retry_from_held_slot = add_composed_limit_evidence(retry_from_held_slot)
    commitment_evidence_null = copy.deepcopy(composed_sequential_purchase)
    commitment_evidence_null["authority"]["commitmentReceipt"]["evidence"] = None
    commitment_evidence_null = add_composed_limit_evidence(commitment_evidence_null)
    missing_common_receipt = copy.deepcopy(composed_purchase)
    del missing_common_receipt["receipt"]
    empty_required_roles = copy.deepcopy(composed_purchase)
    empty_required_roles["intent"]["operations"][4]["requiredRoles"] = []
    wrong_composed_winner = copy.deepcopy(composed_purchase)
    wrong_composed_winner["receipt"]["winningAttempt"]["nativeTransactionRef"] = {
        "kind": "demos-transaction", "value": "tx-attacker-winner",
    }
    wrong_composed_winner["receipt"] = rebind_receipt_finality(
        wrong_composed_winner["receipt"]
    )
    wrong_composed_winner = add_composed_limit_evidence(wrong_composed_winner)
    cross_work_slot = copy.deepcopy(composed_purchase)
    cross_work_slot["slotAdmission"]["work"]["intent"]["expiresAt"] += 1
    substituted_work_id = ref.work_id(
        cross_work_slot["slotAdmission"]["work"]["intent"]
    )
    cross_work_slot["slotAdmission"]["work"]["workId"] = substituted_work_id
    cross_work_slot["slotAdmission"]["newState"]["workId"] = substituted_work_id
    composed_limit_too_small = copy.deepcopy(composed_purchase)
    too_small_capability = capability()
    too_small_capability["limits"]["maxCanonicalBytes"] = 1
    composed_limit_too_small["capability"] = sign_capability(too_small_capability)
    missing_composed_limit_evidence = copy.deepcopy(composed_purchase)
    del missing_composed_limit_evidence["limitEvidence"]
    missing_current_profile_admission = copy.deepcopy(composed_purchase)
    del missing_current_profile_admission["authority"]["currentProfileAdmission"]
    missing_current_profile_admission = add_composed_limit_evidence(
        missing_current_profile_admission
    )
    stale_current_profile_admission = copy.deepcopy(composed_purchase)
    mutate_current_profile_admission(
        stale_current_profile_admission["authority"],
        ["profile", "dacs1"],
        "0.7",
    )
    stale_current_profile_admission = add_composed_limit_evidence(
        stale_current_profile_admission
    )
    substituted_current_profile_admission = copy.deepcopy(composed_purchase)
    mutate_current_profile_admission(
        substituted_current_profile_admission["authority"],
        ["listingHash"],
        "99" * 32,
    )
    substituted_current_profile_admission = add_composed_limit_evidence(
        substituted_current_profile_admission
    )
    historical_vet_admission = copy.deepcopy(composed_purchase)
    mutate_current_profile_admission(
        historical_vet_admission["authority"],
        ["vetDisposition"],
        "historical-only",
    )
    historical_vet_admission = add_composed_limit_evidence(
        historical_vet_admission
    )
    vet_unadmitted = copy.deepcopy(composed_purchase)
    vet_unadmitted_subject = ref.verify_encoded_evidence(
        vet_unadmitted["authority"]["currentProfileAdmission"],
        "test-current-profile-admission",
        PUBLIC_KEYS,
        ref._CURRENT_PROFILE_ADMISSION_TEST_DOMAIN,
        expected_signer=CLAIMS["network"],
    )
    vet_unadmitted_subject.pop("signature")
    vet_unadmitted_subject.pop("vetDisposition")
    vet_unadmitted["authority"]["currentProfileAdmission"] = encoded_evidence(
        "test-current-profile-admission",
        vet_unadmitted_subject,
        "network",
        ref._CURRENT_PROFILE_ADMISSION_TEST_DOMAIN,
    )
    vet_unadmitted = add_composed_limit_evidence(vet_unadmitted)
    # DACS-1 exact presented-claim resolution: a second canonical-distinct
    # claim with the presenter's CF-3 identity resolves no presenter, while a
    # repeated identical claim collapses to one candidate.
    alternate_buyer_claim = {
        "ref": CLAIMS["buyer"], "metadata": {"displayName": "Alternate buyer"},
    }
    alternate_seller_claim = {
        "ref": CLAIMS["seller"],
        "metadata": {"nativeAccount": "dem-test-alternate-seller"},
    }
    ambiguous_payer = presenter_variant_admission(
        "session", "buyer", [alternate_buyer_claim]
    )
    ambiguous_payee = presenter_variant_admission(
        "session", "seller", [alternate_seller_claim]
    )
    ambiguous_listing_seller = presenter_variant_admission(
        "listing", "seller", [alternate_seller_claim]
    )
    duplicate_payer = presenter_variant_admission(
        "session", "buyer", [{"ref": CLAIMS["buyer"]}]
    )
    # The same collapse applies where the payee's native account is read from
    # its presenter claim, and to the Listing seller.
    identical_seller_claim = {
        "ref": CLAIMS["seller"], "metadata": {"nativeAccount": "dem-test-seller"},
    }
    duplicate_payee = presenter_variant_admission(
        "session", "seller", [identical_seller_claim]
    )
    duplicate_listing_seller = presenter_variant_admission(
        "listing", "seller", [identical_seller_claim]
    )
    duplicate_completion_payee = presenter_variant_admission(
        "session", "seller", [identical_seller_claim], completion=True
    )
    malformed_payer_claim = presenter_variant_admission(
        "session", "buyer", [CLAIMS["buyer"]]
    )
    ambiguous_completion_payer = presenter_variant_admission(
        "session", "buyer", [alternate_buyer_claim], completion=True
    )
    legacy_purchase = purchase_intent()
    legacy_receipt = final_receipt(legacy_purchase)
    legacy_composed_admission = composed_purchase_admission(
        legacy_purchase, legacy_receipt
    )
    composed_proof_limit_too_small = copy.deepcopy(composed_purchase)
    proof_limited_capability = capability()
    proof_limited_capability["limits"]["maxProofBytes"] = 1
    composed_proof_limit_too_small["capability"] = sign_capability(
        proof_limited_capability
    )
    composed_proof_limit_too_small = add_composed_limit_evidence(
        composed_proof_limit_too_small
    )
    composed_final_proof_over_reservation = add_composed_limit_evidence(
        copy.deepcopy(composed_purchase), reservation_bytes=1
    )
    return [
        vector("awp-purchase-composed-admission", ["AWP-3", "AWP-5", "AWP-6", "AWP-7", "AWP-10", "AWP-11", "AWP-12"], "purchase-admission", composed_purchase, "pass", "One fail-closed verifier consumes exact shape, authenticated authority, authorization, slot, winner, receipt, and settlement; co-final admission does not require a standalone commitment receipt.", boundary_rules=["AWP-12"]),
        vector("awp-purchase-current-profile-admission-missing", ["AWP-4", "AWP-7"], "purchase-admission", missing_current_profile_admission, "indeterminate", "Current Atomic execution remains unavailable when verifier-owned RSC, IBH, Vet, LAA, and current-profile admission authority is absent."),
        vector("awp-purchase-current-profile-admission-stale", ["AWP-4", "AWP-7"], "purchase-admission", stale_current_profile_admission, "fail", "A signed admission for a stale DACS-1 profile cannot authorize the advertised current Atomic tuple."),
        vector("awp-purchase-current-profile-listing-substitution", ["AWP-4", "AWP-7"], "purchase-admission", substituted_current_profile_admission, "fail", "Verifier-owned current-profile admission binds the exact signed Listing and rejects a substituted Listing hash."),
        vector("awp-purchase-vet-record-historical-authority", ["AWP-1", "AWP-7"], "purchase-admission", historical_vet_admission, "fail", "An already-signed Vet record admitted only under historical semantics cannot authorize current Atomic execution; current production Vet authorization is required."),
        vector("awp-purchase-vet-record-not-current-admitted", ["AWP-1", "AWP-7"], "purchase-admission", vet_unadmitted, "indeterminate", "A current-profile admission covering RSC, IBH, and LAA but carrying no current Vet authorization result for the Work's exact signed Vet records is missing authority under AWP-7 and cannot authorize execution."),
        vector("awp-purchase-payer-presenter-ambiguous", ["AWP-4", "AWP-7"], "purchase-admission", ambiguous_payer, "fail", "A re-signed payer IdentityBundle with two canonical-distinct claims for its presentedBy identity resolves no presenter, so whole-profile admission rejects although every bound hash and signature is valid."),
        vector("awp-purchase-payee-presenter-ambiguous", ["AWP-4", "AWP-7"], "purchase-admission", ambiguous_payee, "fail", "A re-signed payee IdentityBundle with two canonical-distinct claims for its presentedBy identity resolves no presenter, so whole-profile admission rejects although every bound hash and signature is valid."),
        vector("awp-purchase-listing-seller-presenter-ambiguous", ["AWP-4", "AWP-7"], "purchase-admission", ambiguous_listing_seller, "fail", "A re-signed Listing whose seller IdentityBundle has two canonical-distinct claims for its presentedBy identity resolves no Listing publisher."),
        vector("awp-purchase-presenter-identical-duplicate", ["AWP-4", "AWP-7"], "purchase-admission", duplicate_payer, "pass", "A repeated, canonically identical presentedBy claim collapses to one candidate; array order and repetition do not make the presenter ambiguous."),
        vector("awp-purchase-payee-presenter-identical-duplicate", ["AWP-4", "AWP-7"], "purchase-admission", duplicate_payee, "pass", "A repeated, canonically identical payee presentedBy claim collapses to one candidate, including where the payee's native account is read from that claim."),
        vector("awp-purchase-listing-seller-presenter-identical-duplicate", ["AWP-4", "AWP-7"], "purchase-admission", duplicate_listing_seller, "pass", "A repeated, canonically identical Listing seller presentedBy claim collapses to one candidate and still identifies the Listing publisher."),
        vector("awp-completion-payee-presenter-identical-duplicate", ["AWP-4", "AWP-7", "AWP-13"], "completion-admission", duplicate_completion_payee, "pass", "Completion consumes the same collapse of a repeated, canonically identical payee presentedBy claim in the verified Purchase."),
        vector("awp-purchase-payer-bundle-claim-malformed", ["AWP-4", "AWP-7"], "purchase-admission", malformed_payer_claim, "error", "A non-object BundleClaim is an earlier structural error; presented-claim resolution does not skip it or reclassify it as an identity non-match."),
        vector("awp-completion-payer-presenter-ambiguous", ["AWP-4", "AWP-7", "AWP-13"], "completion-admission", ambiguous_completion_payer, "fail", "Completion consumes the same exact presented-claim resolution for the verified Purchase payer bundle."),
        vector("awp-purchase-legacy-agreement-not-current-authority", ["AWP-4", "AWP-7"], "purchase-admission", legacy_composed_admission, "indeterminate", "A historically readable AgreementDocument and commit-agreement phase do not authorize execution under the current Atomic tuple."),
        vector("awp-purchase-signed-sequential-admission", ["AWP-6", "AWP-7", "AWP-12"], "purchase-admission", composed_sequential_purchase, "pass", "A signed sequential gate selection is admitted only with the independently verified finalized commitment AnchorReceipt required before payment.", boundary_rules=["AWP-12"]),
        vector("awp-purchase-caller-gate-mode-mismatch", ["AWP-6"], "purchase-admission", mismatched_gate_copy, "fail", "An unsigned caller authority copy cannot change the proof path selected by the signed Work intent."),
        vector("awp-purchase-agreement-seller-differs-from-listing", ["AWP-7"], "purchase-admission", alternate_seller_admission, "fail", "A fully re-signed Work and Agreement from another seller cannot substitute for the seller identity that published the pinned Listing."),
        vector("awp-purchase-composed-retry-admission", ["AWP-5", "AWP-10", "AWP-11", "AWS-10", "AWS-11"], "purchase-admission", composed_retry, "pass", "A complete retry proves the prior rolled-back Work receipt, advances generation N to N+1, and carries that same generation through the terminal receipt and settlement."),
        vector("awp-composed-slot-transition-derived-claim", ["AWS-4", "AWS-6", "AWP-5"], "purchase-admission", derived_claim, "pass", "Composed Purchase admission derives the claim transition from the signed vacant payment-slot CAS and the authenticated prior state; no caller action label is needed."),
        vector("awp-composed-slot-transition-derived-retry", ["AWS-4", "AWS-11", "AWS-12"], "purchase-admission", derived_retry, "pass", "A signed rolled-back payment-slot CAS admits only the retry transition, which requires the complete authenticated failure-receipt and generation proof."),
        vector("awp-composed-slot-transition-observation-only", ["AWS-4", "AWS-6"], "purchase-admission", observation_only, "fail", "An observation-only slot transition is not composed Purchase admission; admission requires the claim or authenticated retry derived from the signed CAS."),
        vector("awp-composed-slot-transition-committed-observation", ["AWS-4", "AWS-6"], "purchase-admission", committed_observation, "fail", "A committed attempt observation does not turn an observation-only slot transition into composed Purchase admission."),
        vector("awp-composed-slot-transition-caller-mismatch", ["AWS-4"], "purchase-admission", mismatched_transition, "fail", "A caller transition label that differs from the transition derived from the signed payment-slot CAS is rejected."),
        vector("awp-composed-effect-inventory-missing", ["AW-44", "AWS-14"], "purchase-admission", inventory_missing, "indeterminate", "Without the authenticated Work-ledger effect inventory, fencing of late or competing attempts is unavailable."),
        vector("awp-composed-effect-inventory-empty", ["AW-44", "AWS-14"], "purchase-admission", inventory_empty, "fail", "An authenticated effect inventory that omits the ledger-selected winner contradicts the committed Work and cannot establish fencing.", boundary_rules=["AW-44"]),
        vector("awp-composed-effect-inventory-late-attempt", ["AW-44", "AWS-14"], "purchase-admission", inventory_late_effect, "fail", "A ledger-recorded business effect from any attempt other than the winner shows an unfenced late or competing attempt, whether or not that attempt is presented."),
        vector("awp-composed-effect-inventory-other-attempt", ["AW-44", "AWS-14"], "purchase-admission", inventory_other_attempt, "fail", "A single-entry inventory whose attempt is not the ledger-selected winner omits the winner, even when that entry carries the winner's native transaction reference."),
        vector("awp-composed-effect-inventory-winner-reference-mismatch", ["AW-44", "AWS-14"], "purchase-admission", inventory_winner_other_ref, "fail", "An inventory naming the ledger-selected winner with another native transaction reference does not record the winner's authenticated business effect."),
        vector("awp-composed-effect-source-unauthenticated", ["AW-44", "AWS-14"], "purchase-admission", unauthenticated_effects, "fail", "AW-44/AWS-14: business effects are established only by the authenticated Work-ledger inventory; an effect list outside it is not ledger authority."),
        vector("awp-composed-effect-source-unauthenticated-late-inventory", ["AW-44", "AWS-14"], "purchase-admission", unauthenticated_effects_late, "fail", "An effect list outside the authenticated Work-ledger inventory is not ledger authority, even beside an inventory that records a later effect."),
        vector("awp-composed-effect-inventory-other-block", ["AW-44", "AWS-14"], "purchase-admission", inventory_other_block, "fail", "A valid network-signed inventory taken at a block other than the finalized receipt block does not establish that receipt's business effects."),
        vector("awp-composed-effect-inventory-participant-signed", ["AW-44", "AWS-14"], "purchase-admission", inventory_participant_signed, "fail", "An inventory signed by a party to the Purchase rather than the network is not Work-ledger evidence, even when its signature verifies and its entries name only the winner."),
        vector("awp-composed-effect-inventory-signature-invalid", ["AW-44", "AWS-14"], "purchase-admission", inventory_signature_invalid, "fail", "Removing an entry from a network-signed inventory invalidates the network signature; the altered inventory does not establish business effects."),
        vector("awp-composed-effect-inventory-unsigned", ["AW-44", "AWS-14"], "purchase-admission", inventory_unsigned, "indeterminate", "An unsigned inventory is unauthenticated, so the Work-ledger business effects remain unavailable."),
        vector("awp-composed-effect-inventory-other-work", ["AW-44", "AWS-14"], "purchase-admission", inventory_other_work, "fail", "A network-signed inventory for another Work does not establish this Work's business effects."),
        vector("awp-composed-effect-inventory-other-proof-profile", ["AW-44", "AWS-14"], "purchase-admission", inventory_other_proof_profile, "fail", "A network-signed inventory under another proof profile than the capability selects does not establish business effects for this Work."),
        vector("awp-composed-effect-inventory-other-validator-set", ["AW-44", "AWS-14"], "purchase-admission", inventory_other_validator_set, "fail", "A network-signed inventory under another validator set than the capability selects does not establish business effects for this Work."),
        vector("awp-composed-effect-inventory-repeated-attempt", ["AW-44", "AWS-14"], "purchase-admission", inventory_repeated_winner, "fail", "An inventory that lists the same attempt twice is malformed ledger evidence and cannot establish the winner's single business effect."),
        vector("awp-composed-effect-source-caller-empty", ["AW-44", "AWS-14"], "purchase-admission", caller_empty_effects, "fail", "An empty effect list outside the authenticated Work-ledger inventory is not ledger authority, even beside the inventory that records only the winner."),
        vector("awp-composed-effect-inventory-unknown-member", ["AW-44", "AWS-14"], "purchase-admission", inventory_unknown_member, "fail", "A network-signed inventory carrying a member outside its closed shape is malformed ledger evidence and cannot establish business effects."),
        vector("awp-composed-effect-inventory-entry-unknown-member", ["AW-44", "AWS-14"], "purchase-admission", inventory_entry_unknown_member, "fail", "An inventory entry carrying a member outside its closed attempt and native-reference shape is malformed ledger evidence, even when the inventory's network signature verifies."),
        vector("awp-composed-effect-inventory-version-unsupported", ["AW-44", "AWS-14"], "purchase-admission", inventory_version_unsupported, "fail", "A network-signed inventory with an unsupported inventoryVersion is not the synthetic Work-ledger inventory this candidate defines and cannot establish business effects."),
        vector("awp-completion-composed-effect-inventory-late-attempt", ["AW-44", "AWS-14", "AWP-13"], "completion-admission", completion_inventory_late_effect, "fail", "Completion admission takes business effects from the same Work-ledger inventory; a recorded effect from an attempt other than the winner shows an unfenced late or competing attempt."),
        vector("awp-composed-slot-retry-caller-observation-ignored", ["AWS-4", "AWS-11"], "purchase-admission", retry_from_held_slot, "fail", "A derived retry whose authenticated prior slot is held rather than rolled back contradicts the signed CAS; a caller's unresolved attempt observation does not make composed admission indeterminate."),
        vector("awp-purchase-sequential-commitment-evidence-null", ["AWP-6", "AWP-12"], "purchase-admission", commitment_evidence_null, "indeterminate", "A commitment AnchorReceipt whose finality evidence is null cannot satisfy the sequential gate; the missing evidence leaves admission unavailable."),
        vector("awp-purchase-composed-retry-generation-skip", ["AWP-10", "AWP-11", "AWS-10", "AWS-11"], "purchase-admission", composed_retry_generation_skip, "fail", "A retry cannot skip a generation or present a slot transition that differs from its terminal receipt."),
        vector("awp-completion-composed-admission", ["AWP-13", "AWP-14", "AWP-15", "AWP-16"], "completion-admission", composed_completion, "pass", "One Completion verifier consumes the finalized Purchase and exact authority context through delivery settlement."),
        vector("awp-completion-composed-claims-evidence-and-bundle-finalized", ["AWP-16"], "completion-admission", composed_completion_both_claims, "fail", "Supplying both forbidden finalization claims cannot be hidden by the composed verifier's derived false state."),
        vector("awp-completion-gate-mode-differs-from-purchase", ["AWP-13"], "completion-admission", mismatched_completion_admission, "fail", "A signed Completion intent cannot reinterpret the commitment proof path selected by its verified Purchase intent."),
        vector("awp-composed-profile-empty-required-roles", ["AWP-5", "AWP-15"], "purchase-admission", empty_required_roles, "fail", "Exact profile shape is enforced before an empty requiredRoles list can erase authorization requirements.", boundary_rules=["AWP-5", "AWP-15"]),
        vector("awp-composed-common-receipt-missing", ["AWP-11", "AWP-12"], "purchase-admission", missing_common_receipt, "indeterminate", "Co-final admission without its resulting common BFT receipt remains unavailable; it cannot retroactively switch payment paths.", boundary_rules=["AWP-12"]),
        vector("awp-composed-winner-receipt-mismatch", ["AWP-10", "AWP-11"], "purchase-admission", wrong_composed_winner, "fail", "The finalized receipt winner must equal the ledger-authenticated attempt ID and native transaction reference."),
        vector("awp-composed-slot-cross-work-substitution", ["AWP-5", "AWP-10", "AWP-11"], "purchase-admission", cross_work_slot, "fail", "The slot admission, attempt, terminal receipt, and settlement must all name the same outer canonical Work."),
        vector("awp-composed-capability-limit-enforced", ["AWP-5", "AW-71"], "purchase-admission", composed_limit_too_small, "fail", "Whole-profile admission applies the authenticated node byte limit instead of merely verifying the capability signature."),
        vector("awp-composed-limit-evidence-missing", ["AWP-5", "AW-71"], "purchase-admission", missing_composed_limit_evidence, "indeterminate", "Whole-profile admission requires network-authenticated execution-time and proof-byte metrics for the complete Work-result proof closure."),
        vector("awp-composed-proof-reservation-over-limit", ["AWP-5", "AW-71"], "purchase-admission", composed_proof_limit_too_small, "fail", "The proof-profile reservation exceeds maxProofBytes, so the node rejects before executing the isolated business overlay."),
        vector("awp-composed-work-proof-over-limit", ["AWP-5", "AW-71"], "purchase-admission", composed_final_proof_over_reservation, "fail", "A finalized Work-result proof larger than its admitted reservation demonstrates node/profile nonconformance but cannot retroactively roll back the committed Work."),
        vector("awp-purchase-exact-profile", ["AWP-1", "AWP-2", "AWP-3", "AWP-4", "AWP-5", "AWP-20"], "profile", purchase_base, "pass", "Signed Vet artifacts, existing agreement, commitment, slot and payment follow the exact profile.", boundary_rules=["AWP-3", "AWP-5", "AWP-20"]),
        vector("awp-purchase-authenticated-pay-dem", ["AWP-20"], "profile", wrong_purchase_phase, "fail", "Atomic Purchase cannot select another rail phase or mismatch its signed phase tuple."),
        vector("awp-vet-signature-mutation", ["AWP-1", "AWP-2"], "profile", {**purchase_base, "intent": bad_vet}, "fail", "Vet bytes and signature are verified, not trusted as a detached verdict."),
        vector("awp-vet-cf4-address-mismatch", ["AWP-1", "AWP-2"], "profile", {**purchase_base, "intent": wrong_vet_address}, "fail", "A Vet write must use the CF-4 encoded CompositeVerificationRecord address."),
        vector("awp-vet-cas-forbidden", ["AWP-2"], "profile", {**purchase_base, "intent": vet_cas}, "fail", "Atomic Purchase may create a Vet record but cannot CAS-rewrite it."),
        vector("awp-live-vet-action", ["AWP-3"], "profile", {**purchase_base, "intent": live_vet}, "fail", "Nondeterministic live Vet action cannot execute in the rollback overlay.", boundary_rules=["AWP-3"]),
        vector("awp-purchase-order-changed", ["AWP-5", "AWP-6"], "profile", {**purchase_base, "intent": bad_order}, "fail", "Payment cannot move before the signed commitment/slot ordering.", boundary_rules=["AWP-5"]),
        vector("awp-commitment-agreement-binding", ["AWP-4", "AWP-6", "AWP-7"], "profile", {**purchase_base, "intent": bad_commit}, "fail", "The commitment must bind the accepted agreement before payment."),
        vector("awp-commitment-cas-forbidden", ["AWP-6"], "profile", {**purchase_base, "intent": commitment_cas}, "fail", "The commitment gate requires the canonical create-only dacs3 address."),
        vector("awp-commitment-job-binding", ["AWP-4", "AWP-7"], "profile", {**purchase_base, "intent": other_job_commitment_intent}, "fail", "A valid commitment carrying another jobId cannot be used by this Purchase Work."),
        vector("awp-commitment-listing-binding", ["AWP-4", "AWP-7"], "profile", {**purchase_base, "intent": wrong_listing_commitment_intent}, "fail", "A valid commitment must repeat the exact listingRef pinned by the signed agreement."),
        vector("awp-consensus-deadline-last-valid", ["AWP-7", "AWP-8", "AWP-9"], "profile", last_valid_deadline, "pass", "The consensus timestamp one millisecond before notAfter remains valid; client/RPC time is not consulted.", boundary_rules=["AWP-8"]),
        vector("awp-deadline-equality-expired", ["AWP-7", "AWP-8"], "profile", outside_deadline, "fail", "Consensus block time equal to notAfter is outside the half-open validity interval and rejects payment.", boundary_rules=["AWP-8"]),
        vector("awp-client-time-not-authoritative", ["AWP-8", "AWP-9"], "profile", client_time, "fail", "An earlier client/RPC observation time cannot override the expired finalized block timestamp."),
        vector("awp-cofinal-critical-effects", ["AWP-10", "AWP-11"], "profile", purchase_base, "pass", "Commitment, slot and payment share one commit outcome and BFT receipt."),
        vector("awp-partial-critical-effect", ["AWP-10"], "profile", mixed_status, "fail", "Mixed critical outcomes violate co-finality."),
        vector("awp-sequential-gate-when-proof-missing", ["AWP-11", "AWP-12"], "profile", no_bft, "indeterminate", "Without common BFT receipt the atomic alternative is unavailable and sequential CA-1/SR2-8 applies.", boundary_rules=["AWP-12"]),
        vector("awp-completion-exact-profile", ["AWP-13", "AWP-14", "AWP-15", "AWP-16", "AWP-21"], "profile", completion_base, "pass", "Completion verifies Purchase receipt then writes exact delivery bytes; evidence remains for the tail.", boundary_rules=["AWP-15", "AWP-21"]),
        vector("awp-completion-commitment-projection-missing", ["AWP-12", "AWP-13"], "profile", missing_commitment_projection, "indeterminate", "Completion cannot execute until the Purchase commitment storage operation has a finalized complete AnchorReceipt projection."),
        vector("awp-completion-commitment-projection-mismatch", ["AWP-13"], "profile", bad_commitment_projection, "fail", "A contradictory Purchase commitment AnchorReceipt cannot satisfy the Completion gate."),
        vector("awp-completion-authenticated-delivery", ["AWP-21"], "profile", wrong_completion_phase, "fail", "Completion delivery phase index must match the verified signed Listing invocation while retaining the Purchase slot phase.", boundary_rules=["AWP-21"]),
        vector("awp-delivery-content-mismatch", ["AWP-14"], "profile", {**completion_base, "intent": bad_delivery}, "fail", "Delivery bytes must match the agreed content hash."),
        vector("awp-delivery-address-mismatch", ["AWP-14"], "profile", {**completion_base, "intent": wrong_delivery_address}, "fail", "Completion delivery must use dacs4:deliverable:{jobId}."),
        vector("awp-delivery-cas-forbidden", ["AWP-14"], "profile", {**completion_base, "intent": delivery_cas}, "fail", "Atomic Completion delivery is create-only and cannot CAS-rewrite a prior artifact."),
        vector("awp-completion-does-not-finalize-bundle", ["AWP-16"], "profile", {**completion_base, "claimsBundleFinalized": True}, "fail", "Completion inclusion alone is not a DACS-5 finalization proof."),
        vector("awp-post-purchase-failure-placeholder", ["AWP-17"], "post-purchase", {"remedy": "ordinary-failure-record", "roleSpecificBundle": True}, "indeterminate", "A Boolean cannot establish a verified role-specific DACS failure record.", boundary_rules=["AWP-17"]),
        vector("awp-post-purchase-failure-cannot-undo-payment", ["AWP-17"], "post-purchase", {"remedy": "undo-original-payment"}, "fail", "An ordinary post-Purchase failure cannot reverse the original committed payment; it requires a new compensating artifact.", boundary_rules=["AWP-17"]),
        vector("awp-refund-amendment-placeholder", ["AWP-18"], "post-purchase", {"remedy": "settlement-amendment", "originalEvidenceId": "settlement-original-1", "amendment": artifact("settlement-amendment", "payer", {"originalEvidenceId": "settlement-original-1", "reason": "refund"}), "publicKeys": PUBLIC_KEYS}, "indeterminate", "A generic artifact is not a versioned SettlementAmendment and does not prove the original evidence publication.", boundary_rules=["AWP-18"]),
        vector("awp-unlinked-refund", ["AWP-18"], "post-purchase", {"remedy": "settlement-amendment", "originalEvidenceId": "settlement-original-1", "amendment": artifact("settlement-amendment", "payer", {"originalEvidenceId": "other", "reason": "refund"}), "publicKeys": PUBLIC_KEYS}, "fail", "An unlinked correction cannot mutate original settlement history.", boundary_rules=["AWP-18"]),
        vector("awp-fair-exchange-profile-placeholder", ["AWP-19"], "post-purchase", {"remedy": "guaranteed-delivery", "profile": "escrow-v1"}, "indeterminate", "The amendment does not fabricate an escrow profile that has not been standardized.", boundary_rules=["AWP-19"]),
        vector("awp-fair-exchange-claim-without-profile", ["AWP-19"], "post-purchase", {"remedy": "guaranteed-delivery", "profile": "dacs-completion-v1"}, "fail", "Atomic Work alone does not provide fair exchange between Purchase and Completion.", boundary_rules=["AWP-19"]),
    ]


def slot_base() -> tuple[dict[str, Any], dict[str, Any], str]:
    intent = purchase_intent()
    key = copy.deepcopy(intent["operations"][4]["payload"]["slotKey"])
    agreement = intent["operations"][2]["payload"]["artifact"]
    conflict = {
        **key, "agreementHash": ref._agreement_hash(agreement),
        "commitmentLogicalAddress": intent["operations"][3]["payload"]["logicalAddress"],
        "payer": "dem-test-payer", "payee": "dem-test-seller", "asset": "DEM", "amount": "10",
    }
    return key, conflict, ref.conflict_digest(conflict)


def settlement_evidence(
    intent: dict[str, Any], receipt: dict[str, Any], operation_id: str,
    outcome: str = "success", reason: str | None = None,
) -> dict[str, Any]:
    receipt_content_hash = ref.receipt_hash(receipt)
    leaf = next(v for v in receipt["operationResults"] if v["operationId"] == operation_id)
    index = leaf["operationIndex"]
    operation_ref = {
        "kind": "demos-work-operation-v1",
        "networkId": intent["networkId"],
        "workId": receipt["workId"],
        "operationIndex": index,
        "operationId": operation_id,
        "operationKind": leaf["operationKind"],
    }
    proof_subject = {
        "networkId": receipt["networkId"],
        "workId": receipt["workId"],
        "winningAttemptId": receipt["winningAttempt"]["attemptId"],
        "operationReceiptRoot": receipt["operationReceiptRoot"],
        "operationIndex": index,
        "operationId": operation_id,
        "operationKind": leaf["operationKind"],
        "receiptContentHash": receipt_content_hash,
    }
    evidence = {
        "atomicEvidenceVersion": "1",
        "networkId": intent["networkId"],
        "jobId": intent["jobId"],
        "railId": intent["railId"],
        "phaseIndex": intent["phaseIndex"],
        "phase": "pay-dem" if leaf["operationKind"] == "native-dem-transfer" else "deliver-storage-program",
        "outcome": outcome,
        "operationRef": operation_ref,
        "workReceiptRef": {
            "refVersion": "1",
            "networkId": receipt["networkId"],
            "workId": receipt["workId"],
            "receiptCommitment": receipt["receiptCommitment"],
            "contentHash": receipt_content_hash,
            "locator": {"kind": "demos-work-receipt-v1", "value": receipt["workId"]},
        },
        "operationProof": {
            "proofProfile": "demos-bft-proof/test-1",
            "subject": proof_subject,
            "value": ref.b64u(ref.jcs_bytes(ref.inclusion_path(receipt["operationResults"], index))),
        },
        "observedAt": receipt["blockRef"]["timestamp"],
    }
    if outcome == "failure":
        if reason is not None:
            evidence["reason"] = reason
    elif leaf["operationKind"] == "native-dem-transfer":
        payload = intent["operations"][index]["payload"]
        evidence["paymentAmount"] = {"amount": payload["amount"], "currency": payload["asset"]}
        evidence["settlementFinality"] = {
            "model": "bft-final",
            "finalityObservedAt": receipt["blockRef"]["timestamp"],
        }
    else:
        storage = leaf["storageOutput"]
        evidence["deliverableContentHash"] = storage["contentHash"]
        evidence["deliverableAnchor"] = {
            "kind": "storage-program", "locator": storage["logicalAddress"]
        }
    return ref.sign_embedded(
        evidence, CLAIMS["orchestrator"], SEEDS["orchestrator"], ref.EVIDENCE_DOMAIN
    )


def resign_atomic_evidence(evidence: dict[str, Any], role: str = "orchestrator") -> dict[str, Any]:
    return ref.sign_embedded(
        {k: copy.deepcopy(v) for k, v in evidence.items() if k != "signature"},
        CLAIMS[role], SEEDS[role], ref.EVIDENCE_DOMAIN,
    )


def atomic_publication(
    evidence: dict[str, Any], address: str, *, mode: str = "create-only",
    existing_evidence: dict[str, Any] | None = None,
    anchor_address: str | None = None, content_hash: str | None = None,
    state: str = "finalized",
) -> dict[str, Any]:
    canonical_bytes = ref.jcs_bytes(evidence)
    logical_address = anchor_address or address
    bound_hash = content_hash or ref.sha256_hex(canonical_bytes)
    native_address = "stor-" + ref.sha256_hex(logical_address.encode())[:40]
    transaction_ref = {
        "kind": "demos-transaction",
        "value": "tx-audit-" + ref.sha256_hex(canonical_bytes)[:16],
    }
    block_ref = {
        "id": "block-audit-950", "height": "950",
        "timestamp": 1_800_000_040_000,
    }
    writer = "native:audit-relay-1"
    nonce = "950"
    write_condition_result = (
        {
            "kind": "create-only", "disposition": "reconciled-identical",
            "priorState": {
                "state": "present",
                "contentHash": ref.sha256_hex(
                    ref.jcs_bytes(existing_evidence or evidence)
                ),
            },
        }
        if mode == "replay"
        else {
            "kind": "create-only", "disposition": "created",
            "priorState": {"state": "absent"},
        }
    )
    proof = encoded_evidence(
        "test-anchor-publication",
        {
            "logicalAddress": logical_address,
            "nativeAddress": native_address,
            "contentHash": bound_hash,
            "transactionRef": transaction_ref,
            "writer": writer,
            "nonce": nonce,
            "state": state,
            "blockRef": block_ref,
            "networkId": evidence["networkId"],
            "proofProfile": "demos-bft-proof/test-1",
            "validatorSetId": "test-validator-set-1",
            "writeConditionResult": write_condition_result,
        },
        "network", ref._PUBLICATION_TEST_DOMAIN,
    )
    publication = {
        "mode": mode,
        "canonicalBytes": ref.b64u(canonical_bytes),
        "anchorReceipt": {
            "receiptVersion": "1",
            "substrate": evidence["networkId"],
            "finalityProfile": "demos-bft-proof/test-1",
            "logicalAddress": logical_address,
            "nativeAddress": native_address,
            "contentHash": bound_hash,
            "transactionRef": transaction_ref,
            "writer": writer,
            "nonce": nonce,
            "state": state,
            "observationDisposition": "established",
            "observedAt": block_ref["timestamp"] + 500,
            "blockRef": block_ref,
            "evidence": proof,
        },
    }
    if mode == "replay":
        publication["existingCanonicalBytes"] = ref.b64u(
            ref.jcs_bytes(existing_evidence or evidence)
        )
    return publication


def settlement_authority(intent: dict[str, Any]) -> dict[str, Any]:
    if intent["profile"] == "dacs-purchase-v1":
        return authorization_authority(intent)
    purchase = purchase_intent(intent["jobId"])
    authority = authorization_authority(purchase)
    authority["purchaseIntent"] = purchase
    return authority


def composed_attempt(
    intent: dict[str, Any], receipt: dict[str, Any]
) -> dict[str, Any]:
    native_ref = copy.deepcopy(receipt["winningAttempt"]["nativeTransactionRef"])
    attempt_id = receipt["winningAttempt"]["attemptId"]
    return {
        "attemptVersion": "1", "attemptClass": "normal",
        "workId": ref.work_id(intent),
        "attemptId": attempt_id, "nativeTransactionRef": native_ref,
        "canonicalWorkBytes": ref.canonicalize(intent),
        "authorizations": authorizations(intent),
        "nonce": f"attempt-nonce-{attempt_id.removeprefix('attempt-')}",
        "fee": "1",
        "lifecycleEvidence": ledger_evidence(
            attempt_id, ref.work_id(intent), "included-committed", native_ref
        ),
    }


def add_proof_reservation(
    value: dict[str, Any], reserved_bytes: int,
) -> None:
    cap = value["capability"]
    value["proofReservationBytes"] = reserved_bytes
    value["proofReservationEvidence"] = encoded_evidence(
        "test-work-proof-reservation",
        {
            "workId": ref.work_id(value["intent"]),
            "reservedProofBytes": reserved_bytes,
            "reservationRule": "test-fixed-proof-reservation/1",
            "proofProfile": cap["proofProfile"],
            "validatorSetId": cap["validatorSetId"],
        },
        "network", ref._LIMITS_TEST_DOMAIN,
    )


def limit_metrics_evidence(
    value: dict[str, Any], material: dict[str, Any], execution_time_ms: int,
) -> dict[str, Any]:
    cap = value["capability"]
    proof_bytes = len(ref.proof_package_bytes(
        material, value["proofReservationEvidence"],
    ))
    metrics = {
        "workId": ref.work_id(value["intent"]),
        "executionTimeMs": execution_time_ms,
        "proofMaterialHash": ref.sha256_hex(ref.jcs_bytes(material)),
        "proofBytes": proof_bytes,
        "proofProfile": cap["proofProfile"],
        "validatorSetId": cap["validatorSetId"],
    }
    return encoded_evidence(
        "test-work-limit-metrics", metrics, "network",
        ref._LIMITS_TEST_DOMAIN,
    )


def add_composed_limit_evidence(
    value: dict[str, Any], *,
    reservation_bytes: int = COMPOSED_PROOF_RESERVATION_BYTES,
) -> dict[str, Any]:
    add_proof_reservation(value, reservation_bytes)
    material = ref.composed_proof_material(value)
    value["limitEvidence"] = limit_metrics_evidence(
        value, material, 100,
    )
    return value


def add_focused_limit_evidence(
    value: dict[str, Any], *, reservation_bytes: int | None = None,
) -> dict[str, Any]:
    cap = value["capability"]
    add_proof_reservation(
        value,
        cap["limits"]["maxProofBytes"]
        if reservation_bytes is None else reservation_bytes,
    )
    value["limitEvidence"] = limit_metrics_evidence(
        value, value["proofMaterial"], value["executionTimeMs"],
    )
    return value


def focused_proof_package_with_size(
    value: dict[str, Any], size: int,
) -> dict[str, Any]:
    """Pad focused proof material until the entire canonical package is exact."""
    out = copy.deepcopy(value)
    out["proofMaterial"] = {"proofVersion": "test-1", "padding": ""}
    for _ in range(8):
        add_focused_limit_evidence(out, reservation_bytes=size)
        current = len(ref.proof_package_bytes(
            out["proofMaterial"], out["proofReservationEvidence"],
        ))
        if current == size:
            return out
        material_size = len(ref.jcs_bytes(out["proofMaterial"]))
        out["proofMaterial"] = proof_material_with_canonical_size(
            material_size + size - current
        )
    raise AssertionError("focused proof package did not reach the exact size")


def composed_purchase_admission(
    intent: dict[str, Any], receipt: dict[str, Any], *,
    failure_intent: dict[str, Any] | None = None,
    failure_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    authority = authorization_authority(intent)
    if intent["gateMode"] == "co-final":
        authority.pop("commitmentReceipt", None)
    slot_payload = intent["operations"][4]["payload"]
    slot_key = copy.deepcopy(slot_payload["slotKey"])
    is_retry = failure_intent is not None or failure_receipt is not None
    if is_retry and not (
        isinstance(failure_intent, dict) and isinstance(failure_receipt, dict)
    ):
        raise ValueError("composed retry requires both failure intent and receipt")
    prior_slot_state = (
        copy.deepcopy(failure_receipt["paymentSlot"]["after"])
        if is_retry else copy.deepcopy(slot_payload["expected"])
    )
    transition_generation = (
        prior_slot_state["generation"] + 1
        if is_retry else prior_slot_state["generation"]
    )
    work_identifier = ref.work_id(intent)
    evidence = settlement_evidence(intent, receipt, "payment")
    evidence_address = ref.atomic_evidence_address(
        evidence, receipt["paymentSlot"]["after"]["generation"]
    )
    value = {
        "intent": intent, "claimedWorkId": work_identifier,
        "capability": capability(),
        "authorizations": authorizations(intent), "authority": authority,
        "slotAdmission": {
            "ledgerProof": slot_proof(
                slot_key, prior_slot_state
            ),
            "key": slot_key, "work": {
                "workId": work_identifier, "intent": intent,
            },
            "conflictDigest": slot_payload["conflictDigest"],
            "action": "retry" if is_retry else "claim",
            "newState": {
                "state": "in-flight",
                "generation": transition_generation,
                "workId": work_identifier,
                "conflictDigest": slot_payload["conflictDigest"],
            },
        },
        "attempts": [composed_attempt(intent, receipt)],
        "winningAttemptId": receipt["winningAttempt"]["attemptId"],
        "ledgerInventory": effect_inventory(
            work_identifier,
            [(
                receipt["winningAttempt"]["attemptId"],
                receipt["winningAttempt"]["nativeTransactionRef"],
            )],
            block_id=receipt["blockRef"]["id"],
        ),
        "receipt": receipt,
        "settlement": {
            "evidence": evidence,
            "authenticatedContext": {
                "networkId": intent["networkId"], "jobId": intent["jobId"],
                "railId": intent["railId"], "phaseIndex": intent["phaseIndex"],
            },
            "pc2Address": (
                f"dacs4:payment:{intent['jobId']}:"
                f"{ref.cf4_encode(intent['railId'])}:{intent['phaseIndex']}"
            ),
            "settlementId": ref.settlement_id(evidence["operationRef"]),
            "evidenceAddress": evidence_address,
            "auditWrite": {"resubmitsPayment": False},
            "auditPublication": atomic_publication(evidence, evidence_address),
        },
        "publicKeys": PUBLIC_KEYS,
    }
    if is_retry:
        value["slotAdmission"].update({
            "failureIntent": failure_intent,
            "failureReceipt": failure_receipt,
        })
    return add_composed_limit_evidence(value)


def composed_completion_admission(
    purchase: dict[str, Any], purchase_receipt: dict[str, Any],
    intent: dict[str, Any], receipt: dict[str, Any],
) -> dict[str, Any]:
    authority = authorization_authority(purchase)
    if purchase["gateMode"] == "co-final":
        authority.pop("commitmentReceipt", None)
    authority["purchaseIntent"] = purchase
    evidence = settlement_evidence(intent, receipt, "delivery")
    evidence_address = ref.atomic_evidence_address(evidence)
    value = {
        "intent": intent, "claimedWorkId": ref.work_id(intent),
        "capability": capability(),
        "purchaseIntent": purchase, "purchaseReceipt": purchase_receipt,
        "purchaseCommitmentProjection": projected_anchor_fixture(
            purchase, purchase_receipt, 3
        ),
        "authorizations": authorizations(intent), "authority": authority,
        "attempts": [composed_attempt(intent, receipt)],
        "winningAttemptId": receipt["winningAttempt"]["attemptId"],
        "ledgerInventory": effect_inventory(
            ref.work_id(intent),
            [(
                receipt["winningAttempt"]["attemptId"],
                receipt["winningAttempt"]["nativeTransactionRef"],
            )],
            block_id=receipt["blockRef"]["id"],
        ),
        "receipt": receipt,
        "settlement": {
            "evidence": evidence,
            "authenticatedContext": {
                "networkId": intent["networkId"], "jobId": intent["jobId"],
                "railId": intent["railId"], "phaseIndex": intent["phaseIndex"],
            },
            "settlementId": ref.settlement_id(evidence["operationRef"]),
            "evidenceAddress": evidence_address,
            "auditWrite": {"resubmitsPayment": False},
            "auditPublication": atomic_publication(evidence, evidence_address),
        },
        "publicKeys": PUBLIC_KEYS,
    }
    return add_composed_limit_evidence(value)


def presenter_variant_admission(
    scope: str, role: str, records: list[Any], *, completion: bool = False,
) -> dict[str, Any]:
    """Build a complete current-profile admission around one bundle variant.

    The Work, Vet records, agreement, Listing, receipts, settlement,
    current-profile admission and limit evidence are all derived from the
    variant bundle, so only presented-claim resolution can distinguish it.
    """
    with extra_bundle_claims(scope, role, records):
        purchase = purchase_intent(current_profile=True)
        purchase_receipt = final_receipt(purchase)
        if not completion:
            return composed_purchase_admission(purchase, purchase_receipt)
        completion_work = completion_intent(purchase_receipt)
        return composed_completion_admission(
            purchase, purchase_receipt, completion_work,
            final_receipt(completion_work),
        )


def settlement_slot_vectors() -> list[dict[str, Any]]:
    key, conflict, digest = slot_base()
    claim_intent = purchase_intent()
    wid = ref.work_id(claim_intent)
    vacant = {"state": "vacant", "generation": 0}
    inflight = {"state": "in-flight", "generation": 0, "workId": wid, "conflictDigest": digest}
    settled = {"state": "settled", "generation": 0, "workId": wid, "conflictDigest": digest, "receiptCommitment": "ab" * 32}
    failure_intent = claim_intent
    failure_receipt = final_receipt(failure_intent, "rolled-back", 4)
    rolled = copy.deepcopy(failure_receipt["paymentSlot"]["after"])
    claim_input = {"key": key, "conflictDigest": digest, "ledgerProof": slot_proof(key, vacant), "action": "claim", "work": {"workId": wid, "intent": claim_intent}, "newState": inflight, "publicKeys": PUBLIC_KEYS}
    boolean_proof_generation = copy.deepcopy(claim_input)
    boolean_proof_generation["ledgerProof"]["state"]["generation"] = False
    boolean_proof_generation["ledgerProof"] = resign_ledger_proof(
        boolean_proof_generation["ledgerProof"]
    )
    boolean_new_state_generation = mutate(
        claim_input, ["newState", "generation"], False
    )
    wrong_slot_proof_profile = copy.deepcopy(claim_input)
    wrong_slot_proof_profile["ledgerProof"]["proofProfile"] = "attacker-proof/1"
    wrong_slot_proof_profile["ledgerProof"] = resign_ledger_proof(
        wrong_slot_proof_profile["ledgerProof"]
    )
    cf3_slot_identity = copy.deepcopy(claim_input)
    cf3_slot_identity["slotAuthority"] = authorization_authority(claim_intent)
    cf3_slot_identity["slotAuthority"]["paymentPhaseInput"]["payer"][
        "primaryClaim"
    ] += "?jurisdiction=US"
    other_job_commitment_input = copy.deepcopy(claim_input)
    other_job_commitment = finality_commitment(
        "01K1DPA0000000000000000001",
        claim_intent["operations"][2]["payload"]["artifact"],
    )
    other_job_authority = authorization_authority(claim_intent)
    other_job_authority["finalityCommitment"] = other_job_commitment
    other_job_authority["commitmentReceipt"] = commitment_anchor_receipt(
        other_job_commitment
    )
    other_job_commitment_input["slotAuthority"] = other_job_authority

    arbitrary_payer_intent = copy.deepcopy(claim_intent)
    arbitrary_payer_intent["operations"][5]["payload"]["from"] = "dem-attacker-payer"
    arbitrary_payer_conflict = {**conflict, "payer": "dem-attacker-payer"}
    arbitrary_payer_digest = ref.conflict_digest(arbitrary_payer_conflict)
    arbitrary_payer_intent["operations"][4]["payload"][
        "conflictDigest"
    ] = arbitrary_payer_digest
    arbitrary_payer_work_id = ref.work_id(arbitrary_payer_intent)
    arbitrary_payer = {
        **copy.deepcopy(claim_input),
        "conflictDigest": arbitrary_payer_digest,
        "work": {
            "workId": arbitrary_payer_work_id,
            "intent": arbitrary_payer_intent,
        },
        "newState": {
            **inflight,
            "workId": arbitrary_payer_work_id,
            "conflictDigest": arbitrary_payer_digest,
        },
    }
    arbitrary_payee_intent = copy.deepcopy(claim_intent)
    arbitrary_payee_intent["operations"][5]["payload"]["to"] = "dem-attacker-payee"
    arbitrary_payee_conflict = {**conflict, "payee": "dem-attacker-payee"}
    arbitrary_payee_digest = ref.conflict_digest(arbitrary_payee_conflict)
    arbitrary_payee_intent["operations"][4]["payload"][
        "conflictDigest"
    ] = arbitrary_payee_digest
    arbitrary_payee_work_id = ref.work_id(arbitrary_payee_intent)
    arbitrary_payee = {
        **copy.deepcopy(claim_input),
        "conflictDigest": arbitrary_payee_digest,
        "work": {
            "workId": arbitrary_payee_work_id,
            "intent": arbitrary_payee_intent,
        },
        "newState": {
            **inflight,
            "workId": arbitrary_payee_work_id,
            "conflictDigest": arbitrary_payee_digest,
        },
    }
    arbitrary_roster_intent = mutate(
        claim_intent, ["roleRoster", 3, "nativeAccount"], "dem-attacker-payer"
    )
    arbitrary_roster_work_id = ref.work_id(arbitrary_roster_intent)
    arbitrary_roster_account = {
        **copy.deepcopy(claim_input),
        "work": {
            "workId": arbitrary_roster_work_id,
            "intent": arbitrary_roster_intent,
        },
        "newState": {**inflight, "workId": arbitrary_roster_work_id},
    }
    type_mismatch = mutate(claim_input, ["key", "phaseIndex"], "0")
    proof_tuple_mismatch = mutate(claim_input, ["ledgerProof", "key", "jobId"], "01K1DPA0000000000000000001")
    payment_before_slot_intent = copy.deepcopy(claim_intent)
    payment_before_slot_intent["operations"][4] = {
        **copy.deepcopy(claim_intent["operations"][5]),
        "dependsOn": ["commitment"],
    }
    payment_before_slot_intent["operations"][5] = {
        **copy.deepcopy(claim_intent["operations"][4]),
        "dependsOn": ["payment"],
    }
    payment_before_slot = copy.deepcopy(claim_input)
    payment_before_slot["work"] = {
        "intent": payment_before_slot_intent,
        "workId": ref.work_id(payment_before_slot_intent),
    }
    payment_before_slot["newState"] = {
        **inflight, "workId": payment_before_slot["work"]["workId"]
    }
    digest_mismatch = mutate(claim_input, ["conflictDigest"], "00" * 32)
    occupied_conflict = {**claim_input, "ledgerProof": slot_proof(key, {**inflight, "conflictDigest": "99" * 32})}
    replay_inflight = {**claim_input, "ledgerProof": slot_proof(key, inflight), "action": "replay", "executesTransfer": False}
    replay_settled = {**claim_input, "ledgerProof": slot_proof(key, settled), "action": "replay", "executesTransfer": False, "returnedReceiptCommitment": settled["receiptCommitment"]}
    retry_intent = purchase_intent(
        generation=0, expected_state="rolled-back",
        prior_failure=rolled["failureReceiptCommitment"],
    )
    retry_work_id = ref.work_id(retry_intent)
    retry = {**claim_input, "ledgerProof": slot_proof(key, rolled), "action": "retry", "work": {"workId": retry_work_id, "intent": retry_intent}, "failureIntent": failure_intent, "failureReceipt": failure_receipt, "newState": {"state": "in-flight", "generation": 1, "workId": retry_work_id, "conflictDigest": digest}}
    retry_committed_receipt = final_receipt(
        retry_intent, prior_slot_state=rolled
    )
    retry_rolled_back_receipt = final_receipt(
        retry_intent, "rolled-back", 4, prior_slot_state=rolled
    )
    retry_wrong_terminal_generation = copy.deepcopy(retry_committed_receipt)
    retry_wrong_terminal_generation["paymentSlot"]["after"]["generation"] = 0
    retry_wrong_terminal_generation = rebind_receipt_finality(
        retry_wrong_terminal_generation
    )
    retry_wrong_state = mutate(retry, ["newState", "state"], "vacant")
    retry_wrong_work = mutate(retry, ["newState", "workId"], "99" * 32)
    retry_wrong_generation = mutate(retry, ["newState", "generation"], 0)
    retry_wrong_digest = mutate(retry, ["newState", "conflictDigest"], "99" * 32)
    retry_wrong_expected = copy.deepcopy(retry)
    retry_wrong_expected["work"]["intent"]["operations"][4]["payload"][
        "expected"
    ]["generation"] = 1
    retry_wrong_expected["work"]["workId"] = ref.work_id(
        retry_wrong_expected["work"]["intent"]
    )
    retry_wrong_expected["newState"]["workId"] = retry_wrong_expected["work"][
        "workId"
    ]
    conflicting_failure_intent = copy.deepcopy(claim_intent)
    conflicting_failure_intent["operations"][4]["payload"][
        "conflictDigest"
    ] = "77" * 32
    conflicting_failure_receipt = final_receipt(
        conflicting_failure_intent, "rolled-back", 4
    )
    conflicting_prior_state = copy.deepcopy(
        conflicting_failure_receipt["paymentSlot"]["after"]
    )
    retry_after_conflicting_failure_intent = purchase_intent(
        generation=0, expected_state="rolled-back",
        prior_failure=conflicting_prior_state["failureReceiptCommitment"],
    )
    retry_after_conflicting_failure_id = ref.work_id(
        retry_after_conflicting_failure_intent
    )
    retry_prior_digest_substitution = {
        **copy.deepcopy(claim_input),
        "ledgerProof": slot_proof(key, conflicting_prior_state),
        "action": "retry",
        "work": {
            "workId": retry_after_conflicting_failure_id,
            "intent": retry_after_conflicting_failure_intent,
        },
        "failureIntent": conflicting_failure_intent,
        "failureReceipt": conflicting_failure_receipt,
        "newState": {
            "state": "in-flight", "generation": 1,
            "workId": retry_after_conflicting_failure_id,
            "conflictDigest": digest,
        },
    }
    stale_replay = copy.deepcopy(replay_inflight)
    stale_replay["work"]["intent"]["expiresAt"] += 1
    slot_listing_substitution = copy.deepcopy(claim_input)
    substituted_authority = authorization_authority(claim_intent)
    substituted_listing = copy.deepcopy(substituted_authority["listing"])
    substituted_listing["pipeline"][2]["parameters"]["rail"] = "attacker-rail"
    substituted_authority["listing"] = resign_listing(substituted_listing)
    slot_listing_substitution["slotAuthority"] = substituted_authority
    indeterminate = {**claim_input, "ledgerProof": slot_proof(key, inflight), "action": "retry", "attemptObservation": "not-found"}
    intent = purchase_intent()
    receipt = final_receipt(intent)
    evidence = settlement_evidence(intent, receipt, "payment")
    operation_ref = evidence["operationRef"]
    payment_identity = ref.settlement_id(operation_ref)
    payment_context = {
        "networkId": intent["networkId"], "jobId": intent["jobId"],
        "railId": intent["railId"], "phaseIndex": intent["phaseIndex"],
    }
    payment_address = ref.atomic_evidence_address(evidence, 0)
    settle_input = {
        "evidence": evidence, "intent": intent, "receipt": receipt,
        "authenticatedContext": payment_context,
        "pc2Address": f"dacs4:payment:{intent['jobId']}:{ref.cf4_encode(intent['railId'])}:{intent['phaseIndex']}",
        "generation": 0,
        "settlementId": payment_identity,
        "evidenceAddress": payment_address,
        "phaseOrchestrator": CLAIMS["orchestrator"], "publicKeys": PUBLIC_KEYS,
        "authority": settlement_authority(intent),
        "auditWrite": {"resubmitsPayment": False},
        "auditPublication": atomic_publication(evidence, payment_address),
    }
    payer_evidence = resign_atomic_evidence(evidence, "payer")
    legacy = mutate(settle_input, ["evidence"], {"kind": "demos-transaction", "value": "demos:tx-test-atomic-a"})
    both_discriminators = copy.deepcopy(settle_input)
    both_discriminators["evidence"]["evidenceVersion"] = "1"
    both_discriminators["evidence"] = resign_atomic_evidence(both_discriminators["evidence"])
    neither_discriminator = copy.deepcopy(settle_input)
    del neither_discriminator["evidence"]["atomicEvidenceVersion"]
    neither_discriminator["evidence"] = resign_atomic_evidence(neither_discriminator["evidence"])
    # AWS-17: atomicEvidenceVersion is exclusive of every other DACS-4
    # evidence selector; each case adds one and re-signs the evidence.
    extra_selector_inputs = {}
    for selector in (
        "deliveryEvidenceVersion", "finalityBoundEvidenceVersion",
        "legacyTransitionEvidenceVersion",
    ):
        extra_selector = copy.deepcopy(settle_input)
        extra_selector["evidence"][selector] = "1"
        extra_selector["evidence"] = resign_atomic_evidence(extra_selector["evidence"])
        extra_selector["auditPublication"] = atomic_publication(
            extra_selector["evidence"], payment_address
        )
        extra_selector_inputs[selector] = extra_selector
    # AWS-19: operationProof.proofProfile equals the capability's proofProfile.
    operation_proof_profile_mismatch = copy.deepcopy(settle_input)
    operation_proof_profile_mismatch["evidence"]["operationProof"][
        "proofProfile"
    ] = "demos-bft-proof/test-0"
    operation_proof_profile_mismatch["evidence"] = resign_atomic_evidence(
        operation_proof_profile_mismatch["evidence"]
    )
    operation_proof_profile_mismatch["auditPublication"] = atomic_publication(
        operation_proof_profile_mismatch["evidence"], payment_address
    )
    wrong_pc2 = mutate(
        settle_input, ["pc2Address"],
        f"dacs4:payment:{intent['jobId']}:x402-usdc:{intent['phaseIndex']}",
    )
    malformed_pc2 = mutate(
        settle_input, ["pc2Address"],
        f"dacs4:payment:{intent['jobId']}:evm%3a1:{intent['phaseIndex']}",
    )
    wrong_receipt_hash = mutate(settle_input, ["evidence", "workReceiptRef", "contentHash"], "00" * 32)
    wrong_receipt_hash["evidence"] = resign_atomic_evidence(wrong_receipt_hash["evidence"])
    wrong_op = mutate(settle_input, ["evidence", "operationRef", "operationId"], "commitment")
    wrong_op["evidence"] = resign_atomic_evidence(wrong_op["evidence"])
    extra_op_ref = copy.deepcopy(settle_input)
    extra_op_ref["evidence"]["operationRef"]["futureMember"] = "must-not-hash"
    extra_op_ref["evidence"]["workReceiptRef"]["futureMember"] = {
        "preserved": True,
    }
    extra_op_ref["evidence"]["workReceiptRef"]["locator"]["futureMember"] = 1
    extra_op_ref["evidence"] = ref.sign_embedded(
        {k: copy.deepcopy(v) for k, v in extra_op_ref["evidence"].items() if k != "signature"},
        CLAIMS["orchestrator"], SEEDS["orchestrator"], ref.EVIDENCE_DOMAIN,
    )
    extra_op_ref["auditPublication"] = atomic_publication(
        extra_op_ref["evidence"], payment_address
    )
    wrong_id = mutate(settle_input, ["settlementId"], "00" * 32)
    wrong_generation_address = mutate(
        settle_input, ["evidenceAddress"], ref.atomic_evidence_address(evidence, 1)
    )
    resubmit = mutate(settle_input, ["auditWrite", "resubmitsPayment"], True)
    missing_receipt = copy.deepcopy(settle_input); del missing_receipt["receipt"]
    failure_receipt = final_receipt(intent, "rolled-back", 4)
    failure_evidence = settlement_evidence(
        intent, failure_receipt, "payment", outcome="failure", reason="atomic-test-failure"
    )
    failure_identity = ref.settlement_id(failure_evidence["operationRef"])
    failure_input = {
        **copy.deepcopy(settle_input), "evidence": failure_evidence,
        "receipt": failure_receipt, "settlementId": failure_identity,
        "evidenceAddress": ref.atomic_evidence_address(failure_evidence, 0),
    }
    failure_input["auditPublication"] = atomic_publication(
        failure_evidence, failure_input["evidenceAddress"]
    )
    failure_wrong_status = copy.deepcopy(failure_input)
    failure_wrong_status["receipt"]["operationResults"][5]["status"] = "committed"
    failure_wrong_status["receipt"]["operationReceiptRoot"] = ref.operation_receipt_root(
        failure_wrong_status["receipt"]["operationResults"]
    )
    failure_wrong_status["receipt"] = rebind_receipt_finality(failure_wrong_status["receipt"])
    failure_missing_reason = copy.deepcopy(failure_input)
    del failure_missing_reason["evidence"]["reason"]
    failure_missing_reason["evidence"] = resign_atomic_evidence(failure_missing_reason["evidence"])
    failure_success_field = copy.deepcopy(failure_input)
    failure_success_field["evidence"]["paymentAmount"] = {"amount": "10", "currency": "DEM"}
    failure_success_field["evidence"] = resign_atomic_evidence(failure_success_field["evidence"])
    failure_missing_proof = copy.deepcopy(failure_input)
    del failure_missing_proof["evidence"]["operationProof"]
    failure_missing_proof["evidence"] = resign_atomic_evidence(failure_missing_proof["evidence"])

    completion = completion_intent(receipt)
    completion_receipt = final_receipt(completion)
    delivery_evidence = settlement_evidence(completion, completion_receipt, "delivery")
    delivery_identity = ref.settlement_id(delivery_evidence["operationRef"])
    delivery_input = {
        "evidence": delivery_evidence, "intent": completion,
        "receipt": completion_receipt,
        "purchaseIntent": intent, "purchaseReceipt": receipt,
        "authenticatedContext": {
            "networkId": completion["networkId"], "jobId": completion["jobId"],
            "railId": completion["railId"], "phaseIndex": completion["phaseIndex"],
        },
        "settlementId": delivery_identity,
        "evidenceAddress": ref.atomic_evidence_address(delivery_evidence),
        "phaseOrchestrator": CLAIMS["orchestrator"], "publicKeys": PUBLIC_KEYS,
        "authority": settlement_authority(completion),
        "auditWrite": {"resubmitsPayment": False},
    }
    delivery_input["auditPublication"] = atomic_publication(
        delivery_evidence, delivery_input["evidenceAddress"]
    )
    bad_delivery = mutate(
        delivery_input, ["evidence", "deliverableContentHash"], "00" * 32
    )
    bad_delivery["evidence"] = resign_atomic_evidence(bad_delivery["evidence"])
    bad_delivery_address = mutate(
        delivery_input, ["evidenceAddress"],
        f"dacs4:delivery:{completion['jobId']}:0:atomic:{delivery_identity}",
    )
    exact_publication_replay = copy.deepcopy(settle_input)
    exact_publication_replay["auditPublication"] = atomic_publication(
        evidence, payment_address, mode="replay", existing_evidence=evidence
    )
    competing_evidence = copy.deepcopy(evidence)
    competing_evidence["futureMember"] = "competing-signed-record"
    competing_evidence = resign_atomic_evidence(competing_evidence)
    competing_publication = copy.deepcopy(settle_input)
    competing_publication["auditPublication"] = atomic_publication(
        evidence, payment_address, mode="replay",
        existing_evidence=competing_evidence,
    )
    wrong_publication_address = copy.deepcopy(settle_input)
    wrong_publication_address["auditPublication"] = atomic_publication(
        evidence, payment_address,
        anchor_address=f"dacs4:atomic:wrong:{payment_identity}",
    )
    wrong_publication_hash = copy.deepcopy(settle_input)
    wrong_publication_hash["auditPublication"] = atomic_publication(
        evidence, payment_address, content_hash="00" * 32,
    )
    unfinalized_publication = copy.deepcopy(settle_input)
    unfinalized_publication["auditPublication"] = atomic_publication(
        evidence, payment_address, state="submitted",
    )
    missing_publication_proof = copy.deepcopy(settle_input)
    del missing_publication_proof["auditPublication"]["anchorReceipt"]["evidence"]
    missing_write_condition = copy.deepcopy(settle_input)
    encoded_publication_proof = missing_write_condition["auditPublication"][
        "anchorReceipt"
    ]["evidence"]
    publication_proof = json.loads(
        ref.b64u_decode(encoded_publication_proof["value"]).decode("utf-8")
    )
    publication_proof.pop("writeConditionResult")
    publication_proof = ref.sign_embedded(
        {k: v for k, v in publication_proof.items() if k != "signature"},
        CLAIMS["network"], SEEDS["network"], ref._PUBLICATION_TEST_DOMAIN,
    )
    encoded_publication_proof["value"] = ref.b64u(ref.jcs_bytes(publication_proof))
    contradictory_prior_state = copy.deepcopy(settle_input)
    contradictory_encoded = contradictory_prior_state["auditPublication"][
        "anchorReceipt"
    ]["evidence"]
    contradictory_proof = json.loads(
        ref.b64u_decode(contradictory_encoded["value"]).decode("utf-8")
    )
    contradictory_proof["writeConditionResult"] = {
        "kind": "create-only", "disposition": "reconciled-identical",
        "priorState": {"state": "present", "contentHash": "99" * 32},
    }
    contradictory_proof = ref.sign_embedded(
        {k: v for k, v in contradictory_proof.items() if k != "signature"},
        CLAIMS["network"], SEEDS["network"], ref._PUBLICATION_TEST_DOMAIN,
    )
    contradictory_encoded["value"] = ref.b64u(ref.jcs_bytes(contradictory_proof))
    unsigned_mode_flip = copy.deepcopy(settle_input)
    unsigned_mode_flip["auditPublication"]["mode"] = "replay"
    unsigned_mode_flip["auditPublication"]["existingCanonicalBytes"] = (
        unsigned_mode_flip["auditPublication"]["canonicalBytes"]
    )
    return [
        vector("aws-structured-network-slot-cas", ["AWS-1", "AWS-2", "AWS-3", "AWS-4", "AWS-5", "AWS-6", "AWS-14"], "slot", claim_input, "pass", "Consensus proof binds the network-scoped structured slot; global CAS precedes payment.", boundary_rules=["AWS-2"]),
        vector("aws-type-strict-phase-index", ["AWS-1", "AWS-2", "AWS-3"], "slot", type_mismatch, "fail", "String phaseIndex and integer phaseIndex are distinct."),
        vector("aws-slot-proof-tuple-mismatch", ["AWS-4", "AWS-5"], "slot", proof_tuple_mismatch, "fail", "Claimant tuple cannot replace the tuple authenticated by the ledger proof."),
        vector("aws-slot-cas-after-payment", ["AWS-6"], "slot", payment_before_slot, "fail", "The signed operation graph cannot place payment before the global CAS."),
        vector("aws-conflict-digest-derived", ["AWS-7"], "slot", claim_input, "pass", "Conflict digest is derived from the complete settlement tuple."),
        vector("aws-commitment-other-job-substitution", ["AWS-7", "AWP-7"], "slot", other_job_commitment_input, "fail", "A valid commitment for another job cannot substitute for the artifact signed inside the Purchase Work."),
        vector("aws-slot-listing-rail-substitution", ["AWS-1", "AWS-7", "AWP-20"], "slot", slot_listing_substitution, "fail", "A re-signed Listing for another rail cannot redefine the Agreement-pinned slot namespace."),
        vector("aws-arbitrary-payer-account", ["AWS-7"], "slot", arbitrary_payer, "fail", "A self-consistent digest and transfer cannot replace the payer account derived from the authenticated paying-key claim."),
        vector("aws-arbitrary-payee-account", ["AWS-7"], "slot", arbitrary_payee, "fail", "A self-consistent digest and transfer cannot replace the payee account derived from the authenticated seller bundle."),
        vector("aws-arbitrary-roster-native-account", ["AWS-7"], "slot", arbitrary_roster_account, "fail", "A signed roleRoster nativeAccount remains an expectation and cannot replace authenticated account derivation."),
        vector("aws-initial-generation-zero", ["AWS-7"], "slot", claim_input, "pass", "Generation zero is the initial signed slot-generation boundary.", boundary=True),
        vector("aws-slot-proof-boolean-generation", ["AWS-2", "AWS-4", "AWS-7"], "slot", boolean_proof_generation, "fail", "A network-signed Boolean false cannot alias authenticated slot generation zero."),
        vector("aws-slot-new-state-boolean-generation", ["AWS-2", "AWS-4", "AWS-7"], "slot", boolean_new_state_generation, "fail", "An unsigned Boolean false cannot alias the claim transition's integer generation zero."),
        vector("aws-slot-cf3-parameter-identity", ["AWS-1", "AWS-7"], "slot", cf3_slot_identity, "pass", "Advisory ClaimReference parameters do not split authenticated payer identity in the slot authority path."),
        vector("aws-slot-proof-profile-mismatch", ["AWS-4", "AWS-7"], "slot", wrong_slot_proof_profile, "fail", "The slot ledger proof binds the capability-selected proof profile and validator set."),
        vector("aws-conflict-digest-mismatch", ["AWS-7", "AWS-8"], "slot", digest_mismatch, "fail", "A different/false digest is rejected before payment.", boundary_rules=["AWS-8"]),
        vector("aws-occupied-slot-conflict", ["AWS-5", "AWS-8"], "slot", occupied_conflict, "fail", "A distinct Work conflict cannot claim an occupied slot."),
        vector("aws-inflight-exact-replay", ["AWS-8", "AWS-9"], "slot", replay_inflight, "pass", "In-flight exact replay reconciles without a transfer.", boundary_rules=["AWS-8"]),
        vector("aws-replay-stale-work-wrapper", ["AWS-9", "AW-39"], "slot", stale_replay, "fail", "Replay recomputes workId from canonical intent before comparing the occupied slot."),
        vector("aws-settled-exact-replay", ["AWS-10"], "slot", replay_settled, "pass", "Settled replay returns the receipt bound by slot state."),
        vector("aws-retry-after-rollback", ["AWS-11", "AWS-12"], "slot", retry, "pass", "The first generation advance binds the generation-zero failure receipt, retains the digest, and derives a new Work.", boundary=True),
        vector("aws-retry-new-state-invalid", ["AWS-11", "AWS-12"], "slot", retry_wrong_state, "fail", "A retry CAS must enter in-flight, not another caller-selected state."),
        vector("aws-retry-workid-invalid", ["AWS-11", "AWS-12"], "slot", retry_wrong_work, "fail", "Retry in-flight state binds the recomputed current Work ID."),
        vector("aws-retry-generation-invalid", ["AWS-11", "AWS-12"], "slot", retry_wrong_generation, "fail", "Retry advances the authenticated rolled-back generation exactly once."),
        vector("aws-retry-conflict-digest-invalid", ["AWS-11", "AWS-12"], "slot", retry_wrong_digest, "fail", "Retry retains the authenticated conflict digest."),
        vector("aws-retry-signed-expected-invalid", ["AWS-11", "AWS-12"], "slot", retry_wrong_expected, "fail", "The signed CAS expectation projects the authenticated rolled-back state at generation N."),
        vector("aws-retry-prior-conflict-digest-substitution", ["AWS-11", "AWS-12"], "slot", retry_prior_digest_substitution, "fail", "A retry cannot cite an internally valid rolled-back failure from a different conflict digest; generation N and N+1 retain one conflict identity."),
        vector("aws-retry-committed-receipt-generation", ["AWS-11", "AWS-12"], "receipt", {"intent": retry_intent, "receipt": retry_committed_receipt, "publicKeys": PUBLIC_KEYS}, "pass", "A successful retry receipt proves complete rolled-back generation N before-state and settled generation N+1 after-state."),
        vector("aws-retry-rollback-receipt-generation", ["AWS-11", "AWS-12"], "receipt", {"intent": retry_intent, "receipt": retry_rolled_back_receipt, "publicKeys": PUBLIC_KEYS}, "pass", "A re-rolled-back retry receipt records the new terminal failure at generation N+1."),
        vector("aws-retry-receipt-terminal-generation-invalid", ["AWS-11", "AWS-12"], "receipt", {"intent": retry_intent, "receipt": retry_wrong_terminal_generation, "publicKeys": PUBLIC_KEYS}, "fail", "A retry receipt cannot retain generation N after executing the N-to-N+1 transition."),
        vector("aws-retry-on-not-found", ["AWS-13", "AWS-14"], "slot", indeterminate, "indeterminate", "Not-found leaves the authoritative slot held.", boundary_rules=["AWS-13"]),
        vector("aws-sessionstore-not-authority", ["AWS-14", "AWS-15"], "slot", {**replay_inflight, "sessionStoreAuthoritative": True}, "fail", "SessionStore cannot override authenticated global slot state."),
        vector("aws-sessionstore-journal-only", ["AWS-15"], "slot", {**replay_inflight, "sessionStoreAuthoritative": False}, "pass", "SessionStore may retain a non-authoritative journal while the authenticated global slot remains the source of truth."),
        vector("aws-distinct-atomic-evidence", ["AWS-16", "AWS-17", "AWS-27"], "settlement", settle_input, "pass", "A versioned, properly authorized evidence artifact preserves the legacy ChainTxRef contract.", boundary_rules=["AWS-16", "AWS-17"]),
        vector("aws-both-evidence-discriminators", ["AWS-17"], "settlement", both_discriminators, "fail", "Atomic and legacy evidence discriminators cannot coexist.", boundary_rules=["AWS-17"]),
        vector("aws-neither-evidence-discriminator", ["AWS-17"], "settlement", neither_discriminator, "fail", "Evidence without either discriminator is rejected before interpretation.", boundary_rules=["AWS-17"]),
        vector("aws-atomic-and-delivery-evidence-discriminators", ["AWS-17"], "settlement", extra_selector_inputs["deliveryEvidenceVersion"], "fail", "The exclusive Atomic discriminator cannot coexist with the DeliveryEvidence selector, even in otherwise valid, re-signed Atomic evidence."),
        vector("aws-atomic-and-finality-bound-evidence-discriminators", ["AWS-17"], "settlement", extra_selector_inputs["finalityBoundEvidenceVersion"], "fail", "The exclusive Atomic discriminator cannot coexist with the FinalityBoundSettlementEvidence selector, even in otherwise valid, re-signed Atomic evidence."),
        vector("aws-atomic-and-legacy-transition-evidence-discriminators", ["AWS-17"], "settlement", extra_selector_inputs["legacyTransitionEvidenceVersion"], "fail", "The exclusive Atomic discriminator cannot coexist with the LegacyTransitionSettlementEvidence selector, even in otherwise valid, re-signed Atomic evidence."),
        vector("aws-operation-proof-profile-mismatch", ["AWS-19"], "settlement", operation_proof_profile_mismatch, "fail", "An operationProof whose proofProfile differs from the authenticated capability's proofProfile is not verified under the selected proof algorithm, even in otherwise valid, re-signed evidence."),
        vector("aws-phase-orchestrator-signature", ["AWS-27"], "settlement", {**settle_input, "evidence": payer_evidence}, "fail", "A payer signature cannot substitute for the authenticated phase orchestrator signature."),
        vector("aws-legacy-txref-not-reinterpreted", ["AWS-16", "AWS-17"], "settlement", legacy, "fail", "demos:{txHash} is not reinterpreted as a Work operation."),
        vector("aws-final-work-receipt-bound", ["AWS-18", "AWS-19", "AWS-20", "AWS-24"], "settlement", settle_input, "pass", "Final receipt, committed operation leaf, operation kind, and settlement payload are verified together.", boundary_rules=["AWS-24"]),
        vector("aws-failure-work-receipt-bound", ["AWS-18", "AWS-19", "AWS-20"], "settlement", failure_input, "pass", "Failure evidence selects a verified rolled-back operation leaf and carries a reason without success-only fields."),
        vector("aws-failure-leaf-status-invalid", ["AWS-20"], "settlement", failure_wrong_status, "fail", "Failure evidence cannot select a committed operation leaf."),
        vector("aws-failure-reason-missing", ["AWS-20"], "settlement", failure_missing_reason, "fail", "Failure evidence requires a non-empty reason."),
        vector("aws-failure-success-field-forbidden", ["AWS-20"], "settlement", failure_success_field, "fail", "Failure evidence cannot carry success-only payment members."),
        vector("aws-failure-proof-missing", ["AWS-20", "AWS-28"], "settlement", failure_missing_proof, "fail", "Settlement evidence missing its schema-required operation proof is rejected before semantic verification."),
        vector("aws-receipt-proof-missing", ["AWS-18", "AWS-28"], "settlement", missing_receipt, "indeterminate", "Missing final Work receipt/proof remains indeterminate."),
        vector("aws-receipt-hash-mismatch", ["AWS-18", "AWS-19", "AWS-28"], "settlement", wrong_receipt_hash, "fail", "Contradictory receipt hash fails."),
        vector("aws-pc2-context-anchoring", ["AWS-21", "AWS-22", "AWS-23"], "settlement", settle_input, "pass", "PC2 job, rail and phase are checked before SB-1/SB-2 projection.", boundary_rules=["AWS-23"]),
        vector("aws-pc2-rail-mismatch", ["AWS-21", "AWS-22", "AWS-23", "AWS-28"], "settlement", wrong_pc2, "fail", "A cross-rail PC2 rebind is rejected.", boundary_rules=["AWS-23"]),
        vector("aws-pc2-malformed-cf4", ["AWS-22", "AWS-23"], "settlement", malformed_pc2, "error", "Lowercase or otherwise non-canonical CF-4 escapes are malformed.", boundary_rules=["AWS-23"]),
        vector("aws-operation-kind-and-leaf", ["AWS-19", "AWS-24"], "settlement", wrong_op, "fail", "Pay evidence must reference its committed payment operation leaf.", boundary_rules=["AWS-24"]),
        vector("aws-versioned-settlement-id", ["AWS-25", "AWS-26"], "settlement", settle_input, "pass", "SB-2 uniqueness uses a new domain-separated identity over the operation reference."),
        vector("aws-sig5-additive-reference-members", ["AWS-25", "AWS-26"], "settlement", extra_op_ref, "pass", "Unknown signed reference members remain authenticated while the six required operation-reference fields alone determine settlement identity."),
        vector("aws-settlement-id-mismatch", ["AWS-25", "AWS-26"], "settlement", wrong_id, "fail", "A claimed settlement identity is independently recomputed."),
        vector("aws-payment-address-generation-mismatch", ["AWS-25", "AWS-28"], "settlement", wrong_generation_address, "fail", "Atomic payment evidence address generation derives from the verified terminal slot, not caller state."),
        vector("aws-atomic-publication-exact-replay", ["AWS-28", "AWS-29"], "settlement", exact_publication_replay, "pass", "A byte-identical replay of the complete signed evidence reconciles against its authenticated finalized publication.", boundary_rules=["AWS-28"]),
        vector("aws-atomic-publication-competing-bytes", ["AWS-28"], "settlement", competing_publication, "fail", "Different signed bytes cannot replay at the immutable Atomic evidence address.", boundary_rules=["AWS-28"]),
        vector("aws-atomic-publication-address-mismatch", ["AWS-28"], "settlement", wrong_publication_address, "fail", "The finalized publication must bind the derived Atomic evidence address."),
        vector("aws-atomic-publication-content-hash-mismatch", ["AWS-28"], "settlement", wrong_publication_hash, "fail", "The publication content hash must cover the complete signed evidence bytes."),
        vector("aws-atomic-publication-unfinalized", ["AWS-28"], "settlement", unfinalized_publication, "fail", "A submitted but unfinalized publication cannot establish Atomic evidence."),
        vector("aws-atomic-publication-proof-missing", ["AWS-28"], "settlement", missing_publication_proof, "indeterminate", "Absent authenticated publication lifecycle proof leaves Atomic evidence publication indeterminate."),
        vector("aws-atomic-publication-write-condition-missing", ["AWS-28"], "settlement", missing_write_condition, "indeterminate", "A finalized write without network-authenticated create-only prior-state evidence remains indeterminate."),
        vector("aws-atomic-publication-prior-state-contradiction", ["AWS-28"], "settlement", contradictory_prior_state, "fail", "Authenticated prior-present different bytes contradict create-only publication."),
        vector("aws-atomic-publication-unsigned-mode-flip", ["AWS-28", "AWS-29"], "settlement", unsigned_mode_flip, "fail", "A caller mode label cannot turn an authenticated vacant create into replay reconciliation."),
        vector("aws-audit-tail-payment-resubmit", ["AWS-27", "AWS-29"], "settlement", resubmit, "fail", "Audit repair cannot replay Purchase payment."),
        vector("aws-delivery-evidence-address", ["AWS-18", "AWS-19", "AWS-20", "AWS-25", "AWS-28"], "settlement", delivery_input, "pass", "Verified Completion storage leaf projects to the exact Atomic delivery address and content.", boundary_rules=["AWS-25"]),
        vector("aws-delivery-content-mismatch", ["AWS-20", "AWS-25"], "settlement", bad_delivery, "fail", "Signed delivery evidence cannot change the content hash proven by its storage leaf.", boundary_rules=["AWS-25"]),
        vector("aws-delivery-address-phase-mismatch", ["AWS-25", "AWS-28"], "settlement", bad_delivery_address, "fail", "Atomic delivery address binds the authenticated delivery phase index and settlement identity.", boundary_rules=["AWS-25"]),
        vector("aws-slot-key-display-collision", ["AWS-1", "AWS-2", "AWS-3", "AWS-23"], "slot-distinction", {"leftKey": key, "rightKey": {**key, "networkId": "demos", "railId": "testnet-atomic:demos-native:DEM"}, "displayKeyLeft": "demos:testnet-atomic:demos-native:DEM:01K1DPA0000000000000000000:0", "displayKeyRight": "demos:testnet-atomic:demos-native:DEM:01K1DPA0000000000000000000:0", "treatedAsSame": False}, "pass", "Network and rail remain separate typed components despite a concatenation collision."),
    ]


def bundle_binding(intent: dict[str, Any], role: str, storage: dict[str, Any]) -> dict[str, Any]:
    value = {
        "bindingVersion": "1",
        "jobId": intent["jobId"],
        "role": role,
        "logicalAddress": storage["logicalAddress"],
        "nativeAddress": storage["nativeAddress"],
        "contentHash": storage["contentHash"],
    }
    return ref.sign_embedded(
        value, CLAIMS[role], SEEDS[role], ref._BINDING_TEST_DOMAIN
    )


def audit_dependency_proofs(
    label: str, receipt: dict[str, Any],
) -> list[dict[str, Any]]:
    proofs = []
    for index, leaf in enumerate(receipt["operationResults"]):
        proofs.append({
            "work": label,
            "operationIndex": index,
            "operationRef": {
                "kind": "demos-work-operation-v1",
                "networkId": receipt["networkId"],
                "workId": receipt["workId"],
                "operationIndex": index,
                "operationId": leaf["operationId"],
                "operationKind": leaf["operationKind"],
            },
            "receiptContentHash": ref.receipt_hash(receipt),
            "leaf": copy.deepcopy(leaf),
            "inclusionPath": ref.inclusion_path(receipt["operationResults"], index),
        })
    return proofs


def audit_role_vectors() -> list[dict[str, Any]]:
    purchase = purchase_intent()
    purchase_receipt = final_receipt(purchase)
    completion = completion_intent(purchase_receipt)
    receipt = final_receipt(completion)
    auths = authorizations(completion)
    verified_agreement = artifact(
        "agreement-role-map", "orchestrator",
        {
            "jobId": completion["jobId"],
            "parties": {
                "buyer": CLAIMS["buyer"],
                "seller": CLAIMS["seller"],
                "orchestrator": CLAIMS["orchestrator"],
                "payer": CLAIMS["payer"],
            },
        },
    )
    bundle_party_map = {
        "buyer": CLAIMS["buyer"], "seller": CLAIMS["seller"],
        "orchestrator": CLAIMS["orchestrator"], "payer": CLAIMS["payer"],
    }
    delivery = receipt["operationResults"][1]
    storage = delivery["storageOutput"]
    binding = bundle_binding(completion, "seller", storage)
    anchor = {"role": "seller", "anchoredByRole": "seller", "logicalAddress": storage["logicalAddress"], "contentHash": storage["contentHash"], "operationRef": {"kind": "demos-work-operation-v1", "networkId": completion["networkId"], "workId": receipt["workId"], "operationId": "delivery"}, "bundleBinding": binding}
    base = {
        "purchaseIntent": purchase, "purchaseReceipt": purchase_receipt,
        "completionIntent": completion, "completionReceipt": receipt,
        "completionAuthorizations": auths,
        "authorizationAuthority": authorization_authority(purchase),
        "agreement": verified_agreement, "bundlePartyMap": bundle_party_map,
        "roleAnchor": anchor, "roleSource": "operation-authorization",
        "outerSubmitter": "native:fee-payer-77", "publicKeys": PUBLIC_KEYS,
        "finalisesFromCompletionReceiptOnly": False,
        "bundleAuthoredInsideCompletion": False,
    }
    completion_only = {**base, "finalisesFromCompletionReceiptOnly": True}
    outer_role = {**base, "roleSource": "outer-submitter"}
    bad_binding = mutate(base, ["roleAnchor", "bundleBinding", "role"], "buyer")
    missing_binding = copy.deepcopy(base); del missing_binding["roleAnchor"]["bundleBinding"]
    wrong_content = mutate(base, ["roleAnchor", "contentHash"], "00" * 32)
    bundle_in_completion = {**base, "bundleAuthoredInsideCompletion": True}
    no_purchase = copy.deepcopy(base)
    del no_purchase["purchaseReceipt"]
    mismatched_purchase = copy.deepcopy(base)
    mismatched_purchase["completionIntent"] = completion_intent(
        final_receipt(purchase_intent("01K1DPA0000000000000000001"))
    )
    forged_roster = copy.deepcopy(base)
    forged_roster["completionIntent"]["roleRoster"][1]["signer"] = CLAIMS["buyer"]
    forged_roster["completionAuthorizations"] = authorizations(forged_roster["completionIntent"])
    for index, authorization in enumerate(forged_roster["completionAuthorizations"]):
        if authorization["role"] == "seller":
            forged_roster["completionAuthorizations"][index] = ref.sign_authorization(
                {k: v for k, v in authorization.items() if k != "value"}, SEEDS["buyer"]
            )
    forged_receipt = final_receipt(forged_roster["completionIntent"])
    forged_roster["completionReceipt"] = forged_receipt
    forged_storage = forged_receipt["operationResults"][1]["storageOutput"]
    forged_binding_value = {
        "bindingVersion": "1", "jobId": forged_roster["completionIntent"]["jobId"],
        "role": "seller", "logicalAddress": forged_storage["logicalAddress"],
        "nativeAddress": forged_storage["nativeAddress"],
        "contentHash": forged_storage["contentHash"],
    }
    forged_binding = ref.sign_embedded(
        forged_binding_value, CLAIMS["buyer"], SEEDS["buyer"], ref._BINDING_TEST_DOMAIN
    )
    forged_roster["roleAnchor"] = {
        **copy.deepcopy(anchor),
        "logicalAddress": forged_storage["logicalAddress"],
        "contentHash": forged_storage["contentHash"],
        "operationRef": {**anchor["operationRef"], "workId": forged_receipt["workId"]},
        "bundleBinding": forged_binding,
    }
    audit_bytes = ref.canonicalize({"bundleVersion": "1", "jobId": completion["jobId"]})
    audit_anchor = {
        "logicalAddress": "stor-" + ref.sha256_hex((completion["jobId"] + "-bundle-seller").encode()),
        "contentHash": ref.sha256_hex(audit_bytes.encode()), "canonicalBytes": audit_bytes,
    }
    audit_native_ref = {"kind": "demos-transaction", "value": "audit-tx-1"}
    audit_evidence = {
        "purchaseIntent": purchase,
        "purchaseReceipt": purchase_receipt,
        "completionIntent": completion,
        "completionReceipt": receipt,
        "dependencyProofs": (
            audit_dependency_proofs("purchase", purchase_receipt)
            + audit_dependency_proofs("completion", receipt)
        ),
        "sessionStateBefore": "audit-pending",
        "sessionStateAfter": "finalised",
        "publicKeys": PUBLIC_KEYS,
    }
    audit = {
        **copy.deepcopy(audit_evidence),
        "operations": [
            {"kind": "storage-program-put", "idempotencyKey": "evidence:payment"},
            {"kind": "storage-program-put", "idempotencyKey": "bundle:seller"},
        ],
        "duplicateEffectCount": 0,
        "priorAnchor": audit_anchor,
        "replayAnchor": copy.deepcopy(audit_anchor),
        "nativeTransactionRef": audit_native_ref,
        "lifecycleEvidence": ledger_evidence(
            "audit-attempt-1", "ab" * 32, "included-committed", audit_native_ref
        ),
    }
    missing_dependency_proof = copy.deepcopy(audit)
    missing_dependency_proof["dependencyProofs"].pop()
    missing_dependency_proof["sessionStateAfter"] = "audit-pending"
    premature_finalisation = copy.deepcopy(missing_dependency_proof)
    premature_finalisation["sessionStateAfter"] = "finalised"
    repair_payment = {"operations": [{"kind": "native-dem-transfer", "idempotencyKey": "repair-payment"}], "duplicateEffectCount": 1}
    replay_audit = {
        **copy.deepcopy(audit_evidence),
        "operations": [
            {"kind": "storage-program-put", "idempotencyKey": "bundle:seller"},
            {"kind": "storage-program-put", "idempotencyKey": "bundle:seller"},
        ],
        "duplicateEffectCount": 0,
        "priorAnchor": audit_anchor,
        "replayAnchor": copy.deepcopy(audit_anchor),
        "nativeTransactionRef": audit_native_ref,
        "lifecycleEvidence": ledger_evidence(
            "audit-attempt-1", "ab" * 32, "included-committed", audit_native_ref
        ),
    }
    overwrite_audit = copy.deepcopy(replay_audit)
    overwrite_audit["replayAnchor"]["canonicalBytes"] += " "
    overwrite_audit["replayAnchor"]["contentHash"] = ref.sha256_hex(
        overwrite_audit["replayAnchor"]["canonicalBytes"].encode()
    )
    return [
        vector("awb-completion-receipt-not-final", ["AWB-1"], "role-anchor", completion_only, "fail", "Completion receipt alone cannot finalize DACS-5."),
        vector("awb-work-carried-bundle-profile-deferred", ["AWB-2", "AWB-3", "AWB-4", "AWB-5", "AWB-6", "AWB-7"], "role-anchor", base, "indeterminate", "The conditional Work-carried bundle proof chain is deferred until a later exact Work profile standardizes bundle bytes and authorization.", boundary_rules=["AWB-2", "AWB-3", "AWB-4", "AWB-5", "AWB-6", "AWB-7"]),
        vector("awb-purchase-evidence-required", ["AWB-2", "AWB-7"], "role-anchor", no_purchase, "indeterminate", "Role anchoring requires independently verified Purchase as well as Completion evidence."),
        vector("awb-purchase-completion-mismatch", ["AWB-2", "AWB-6"], "role-anchor", mismatched_purchase, "indeterminate", "The unstandardized later-Work bundle path cannot establish this proof chain."),
        vector("awb-self-consistent-forged-roster", ["AWB-3", "AWB-4", "AWB-5"], "role-anchor", forged_roster, "indeterminate", "No v1 Work-carried bundle profile exists, so this synthetic roster is not accepted as a bundle-anchor test."),
        vector("awb-outer-writer-not-role", ["AWB-3", "AWB-6"], "role-anchor", outer_role, "indeterminate", "No v1 Work-carried bundle profile exists; native writer never establishes DACS role authority."),
        vector("awb-bundlebinding-role-mismatch", ["AWB-4", "AWB-5"], "role-anchor", bad_binding, "indeterminate", "The conditional Work-carried BundleBinding path remains unstandardized in v1."),
        vector("awb-bundlebinding-missing", ["AWB-4", "AWB-7"], "role-anchor", missing_binding, "indeterminate", "Missing role binding evidence is indeterminate rather than inferred."),
        vector("awb-anchor-content-mismatch", ["AWB-2", "AWB-5", "AWB-7"], "role-anchor", wrong_content, "indeterminate", "No v1 Work profile carries the actual receipt-dependent bundle content to test this conditional proof chain."),
        vector("awb-receipt-dependent-bundle-in-completion", ["AWB-2"], "role-anchor", bundle_in_completion, "fail", "Receipt-dependent bundle bytes cannot be authored inside Completion Work."),
        vector("awb-idempotent-nonpaying-audit-tail", ["AWB-1", "AWB-2", "AWB-8", "AWB-9", "AWB-10"], "audit", audit, "pass", "The audit tail establishes final role anchoring by verifying both finalized Works and every dependency proof before publishing without payment.", boundary_rules=["AWB-8", "AWB-10"]),
        vector("awb-audit-dependency-proof-missing", ["AWB-2", "AWB-10"], "audit", missing_dependency_proof, "indeterminate", "A missing Purchase or Completion operation proof leaves the session audit-pending and audit finalisation indeterminate.", boundary_rules=["AWB-2", "AWB-10"]),
        vector("awb-audit-premature-finalisation", ["AWB-10"], "audit", premature_finalisation, "fail", "The session cannot leave audit-pending while a Purchase or Completion operation proof is missing.", boundary_rules=["AWB-10"]),
        vector("awb-audit-replay-no-duplicate", ["AWB-9"], "audit", replay_audit, "pass", "An authenticated exact lifecycle replay produces no duplicate effect."),
        vector("awb-audit-replay-competing-bytes", ["AWB-8"], "audit", overwrite_audit, "fail", "A cryptographically valid competing-byte write cannot overwrite the immutable audit address.", boundary_rules=["AWB-8"]),
        vector("awb-repair-never-replays-purchase", ["AWB-9"], "audit", repair_payment, "fail", "Repair/finalization never contains payment or slot operations."),
    ]


# Predicate-pinning vectors.  Each one starts from a committed vector or a
# generator fixture and re-derives every dependent signature, hash, root,
# commitment, address and publication, so that only the named predicate is
# violated.  A negative that mutates a signed field without re-signing is
# rejected by the signature check first and does not pin its own rule; the
# guard witnesses in tests/test_atomic_work_vectors.py show which predicate
# each of these vectors moves when it is removed.

@contextlib.contextmanager
def patched_builder(name: str, wrap):
    """Swap one module-level fixture builder so every caller sees the variant."""
    real = globals()[name]
    globals()[name] = wrap(real)
    try:
        yield
    finally:
        globals()[name] = real


def resigned_builder(sign, edit):
    """A builder wrapper that edits the built fixture and then re-signs it."""
    def wrap(real):
        def fake(*args, **kwargs):
            return sign(edit_in_place(real(*args, **kwargs), edit))
        return fake
    return wrap


def edit_in_place(value: dict[str, Any], edit) -> dict[str, Any]:
    edit(value)
    return value


def resign_embedded_as(role: str, domain: bytes):
    def sign(value: dict[str, Any]) -> dict[str, Any]:
        return ref.sign_embedded(
            {k: v for k, v in value.items() if k != "signature"},
            CLAIMS[role], SEEDS[role], domain,
        )
    return sign


def resign_listing_as(role: str):
    def sign(listing: dict[str, Any]) -> dict[str, Any]:
        listing = {k: v for k, v in listing.items() if k != "signature"}
        digest = ref.sha256_hex(ref.jcs_bytes(listing))
        listing["signature"] = {
            "algorithm": "ed25519", "signer": CLAIMS[role],
            "value": ref.b64u(ref.ed25519_sign(
                SEEDS[role], ref._LISTING_DOMAIN + digest.encode("ascii"))),
        }
        return listing
    return sign


def resign_payee_agreement(agreement: dict[str, Any]) -> dict[str, Any]:
    agreement = {k: v for k, v in agreement.items() if k != "signatures"}
    digest = ref.sha256_hex(ref.jcs_bytes(agreement))
    agreement["signatures"] = [
        {"party": CLAIMS[role], "algorithm": "ed25519", "value": ref.b64u(
            ref.ed25519_sign(
                SEEDS[role],
                ref._IDENTITY_BOUND_PAYEE_AGREEMENT_DOMAIN + digest.encode("ascii"),
            ))}
        for role in ("buyer", "seller")
    ]
    return agreement


def composed_variant(
    wraps: tuple[tuple[str, Any], ...] = (), *, edit=None,
    rebuild_limits: bool = True, **intent_kwargs: Any,
) -> dict[str, Any]:
    """Whole-profile Purchase admission built through patched fixture builders."""
    with contextlib.ExitStack() as stack:
        for name, wrap in wraps:
            stack.enter_context(patched_builder(name, wrap))
        intent = purchase_intent(current_profile=True, **intent_kwargs)
        value = composed_purchase_admission(intent, final_receipt(intent))
    if edit is not None:
        edit(value)
        if rebuild_limits:
            add_composed_limit_evidence(value)
    return value


def composed_with_intent(transform) -> dict[str, Any]:
    intent = purchase_intent(current_profile=True)
    transform(intent)
    return composed_purchase_admission(intent, final_receipt(intent))


def recompute_root(receipt: dict[str, Any]) -> dict[str, Any]:
    receipt["operationReceiptRoot"] = ref.operation_receipt_root(receipt["operationResults"])
    return receipt


def resign_state_witness(receipt: dict[str, Any], edit) -> dict[str, Any]:
    """Re-sign the business-state witness and re-derive the three roots."""
    witness = json.loads(ref.b64u_decode(receipt["businessState"]["evidence"]["value"]))
    witness.pop("signature", None)
    edit(witness)
    signed = ref.sign_embedded(witness, CLAIMS["network"], SEEDS["network"], ref._STATE_TEST_DOMAIN)
    receipt["businessState"].update({
        "preRoot": ref.state_root(signed["preState"]),
        "postRoot": ref.state_root(signed["postState"]),
        "effectsRoot": ref.sha256_hex(ref.jcs_bytes({"pre": signed["preState"], "post": signed["postState"]})),
    })
    receipt["businessState"]["evidence"]["value"] = ref.b64u(ref.jcs_bytes(signed))
    return receipt


def completion_receipt_input(receipt_edit=None, outcome: str = "committed") -> dict[str, Any]:
    purchase = purchase_intent()
    purchase_receipt = final_receipt(purchase)
    completion = completion_intent(purchase_receipt)
    receipt = final_receipt(completion, outcome, 1 if outcome == "rolled-back" else None)
    if receipt_edit is not None:
        receipt_edit(receipt)
        receipt = rebind_receipt_finality(recompute_root(receipt))
    return {"intent": completion, "receipt": receipt, "purchaseIntent": purchase,
            "purchaseReceipt": purchase_receipt, "publicKeys": PUBLIC_KEYS}


def resettled(base: dict[str, Any], edit, *, role: str = "orchestrator",
              recompute_id: bool = False) -> dict[str, Any]:
    """Re-sign settlement evidence, re-derive its address and republish it."""
    data = copy.deepcopy(base)
    evidence = copy.deepcopy(data["evidence"])
    edit(evidence)
    evidence = resign_atomic_evidence(evidence, role)
    data["evidence"] = evidence
    if recompute_id:
        data["settlementId"] = ref.settlement_id(evidence["operationRef"])
    generation = (
        data["receipt"]["paymentSlot"]["after"]["generation"]
        if evidence.get("phase") == "pay-dem" else None
    )
    data["evidenceAddress"] = ref.atomic_evidence_address(evidence, generation)
    data["auditPublication"] = atomic_publication(evidence, data["evidenceAddress"])
    return data


def resign_capability_limit(base: dict[str, Any], field: str, value: int) -> dict[str, Any]:
    data = copy.deepcopy(base)
    cap = {k: v for k, v in data["capability"].items() if k != "evidence"}
    cap["limits"][field] = value
    data["capability"] = sign_capability(cap)
    return data


FIXTURE_JOB_ID = "01K1DPA0000000000000000000"
# 26 Crockford characters whose first is 8: 130 bits, so not a JID-1 jobId.
JOB_ID_FIRST_8 = "8" + FIXTURE_JOB_ID[1:]


def predicate_pin_vectors(
    built: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    by_name = {item["name"]: item for vectors in built.values() for item in vectors}

    def base(name: str) -> dict[str, Any]:
        return copy.deepcopy(by_name[name]["input"])

    # ---- identity: AW-10 roster, JID-1, versions, CF-2 grammar -------------
    def without_roles(intent: dict[str, Any], *roles: str) -> dict[str, Any]:
        out = copy.deepcopy(intent)
        out["roleRoster"] = [b for b in out["roleRoster"] if b["role"] not in roles]
        return {"intent": out, "claimedWorkId": ref.work_id(out)}

    purchase = purchase_intent()
    completion = completion_intent(final_receipt(purchase))
    duplicate_operation = base("aw-valid-operation-graph")
    duplicate_operation["intent"]["operations"][-1]["operationId"] = (
        duplicate_operation["intent"]["operations"][0]["operationId"]
    )
    duplicate_operation["intent"]["operations"][-1]["dependsOn"] = []
    largest_job_intent = purchase_intent("7ZZZZZZZZZZZZZZZZZZZZZZZZZ")
    job_id_intents = {
        first: purchase_intent(first + FIXTURE_JOB_ID[1:])
        for first in ("8", "9")
    }
    work_version_two = copy.deepcopy(purchase)
    work_version_two["workVersion"] = "2"
    capability_input = base("aw-capability-authenticated")
    self_declared = copy.deepcopy(capability_input)
    self_declared_cap = {k: v for k, v in self_declared["capability"].items() if k != "evidence"}
    self_declared_cap["networkAuthority"] = CLAIMS["buyer"]
    self_declared["capability"] = sign_capability(self_declared_cap)
    other_capability = copy.deepcopy(capability_input)
    other_capability["capability"]["limits"]["maxOperations"] += 1
    capability_version_two = copy.deepcopy(capability_input)
    version_cap = {k: v for k, v in capability_version_two["capability"].items() if k != "evidence"}
    version_cap["capabilityVersion"] = "2"
    capability_version_two["capability"] = sign_capability(version_cap)
    expiry_after_operation = base("aw-expiry-equality-rejected-before-op")
    expiry_after_operation["executedOperationCount"] = 1

    def claim_variant(suffix: str) -> dict[str, Any]:
        out = copy.deepcopy(purchase)
        out["roleRoster"][0]["signer"] = CLAIMS["buyer"] + suffix
        return {"intent": out}

    identity = [
        vector("aw-v1-purchase-roster-missing-buyer", ["AW-10"], "intent", without_roles(purchase, "buyer"), "fail", "A dacs-purchase-v1 roster carries all four roles; dropping the buyer, who authorizes no Purchase operation, is rejected even under a recomputed workId."),
        vector("aw-v1-purchase-roster-two-roles", ["AW-10"], "intent", without_roles(purchase, "buyer", "seller"), "fail", "An ordered, unique orchestrator-and-payer roster still omits two of the four v1 roles."),
        vector("aw-v1-completion-roster-missing-payer", ["AW-10"], "intent", without_roles(completion, "payer"), "fail", "A dacs-completion-v1 roster carries all four roles; dropping the payer, who authorizes no Completion operation, is rejected."),
        vector("aw-operation-id-duplicate", ["AW-21"], "intent", duplicate_operation, "fail", "Two operations cannot share an operationId even when the graph is otherwise valid."),
        vector("aw-job-id-largest-128-bit", ["AW-6"], "intent", {"intent": largest_job_intent, "claimedWorkId": ref.work_id(largest_job_intent)}, "pass", "The largest 128-bit ULID text form, first character 7, is a canonical JID-1 jobId."),
        *(
            vector(f"aw-job-id-first-character-{first}", ["AW-6"], "intent", {"intent": job_intent, "claimedWorkId": ref.work_id(job_intent)}, "fail", f"A 26-character Crockford string starting with {first} encodes 130 bits and is a malformed JID-1 jobId, not a distinct session.")
            for first, job_intent in job_id_intents.items()
        ),
        vector("aw-work-version-unsupported", ["AW-6"], "intent", {"intent": work_version_two, "claimedWorkId": ref.work_id(work_version_two)}, "fail", "An intent with workVersion 2 is not AtomicDacsWorkIntentV1, whatever identifier its bytes derive."),
        vector("aw-claim-parameter-list-empty", ["AW-8", "AW-10"], "intent", claim_variant("?"), "fail", "A ClaimReference with an empty parameter list is not CF-2 canonical."),
        vector("aw-claim-parameter-missing-equals", ["AW-8", "AW-10"], "intent", claim_variant("?a"), "fail", "A ClaimReference parameter without = is not CF-2 canonical."),
        vector("aw-claim-parameter-lowercase-escape", ["AW-8", "AW-10"], "intent", claim_variant("?a=%2f"), "fail", "A lowercase percent-escape is not the CF-2 uppercase form and is not repaired."),
        vector("aw-claim-parameter-reserved-unescaped", ["AW-8", "AW-10"], "intent", claim_variant("?a=b:c"), "fail", "A reserved character in a ClaimReference parameter value must be percent-escaped."),
        vector("aw-capability-self-declared-authority", ["AW-1"], "capability", self_declared, "fail", "A capability that names and signs its own networkAuthority is not authenticated by the independently pinned network authority."),
        vector("aw-capability-attestation-for-other-capability", ["AW-1"], "capability", other_capability, "fail", "A valid network attestation covers one exact capability; a capability differing in one limit is unattested."),
        vector("aw-capability-version-unsupported", ["AW-1"], "capability", capability_version_two, "fail", "An authenticated capability with capabilityVersion 2 is not AtomicWorkCapabilityV1."),
        vector("aw-expiry-equality-after-first-operation", ["AW-76"], "expiry", expiry_after_operation, "fail", "At expiresAt equality the Work is expired even when a first operation is claimed to have executed.", boundary=True),
    ]

    # ---- authorization: validly signed, wrong envelope or signer ------------
    def resigned_authorization(edit, signer_role: str = "payer", operation: str = "payment") -> dict[str, Any]:
        data = base("aw-auth-complete-envelope")
        auths = data["authorizations"]
        index = next(i for i, a in enumerate(auths) if a["operationId"] == operation)
        envelope = {k: v for k, v in auths[index].items() if k != "value"}
        edit(envelope)
        auths[index] = ref.sign_authorization(envelope, SEEDS[signer_role])
        return data

    other_work = copy.deepcopy(base("aw-auth-complete-envelope")["intent"])
    other_work["expiresAt"] -= 1

    def roster_account(role: str, account: str) -> dict[str, Any]:
        intent = purchase_intent(gate_mode="sequential")
        next(b for b in intent["roleRoster"] if b["role"] == role)["nativeAccount"] = account
        return {"intent": intent, "authorizations": authorizations(intent),
                "authority": authorization_authority(intent), "publicKeys": PUBLIC_KEYS}

    # DACS-4 RTB-1: move exactly one finalized registry receipt past session
    # start; acceptedAt and the other receipt stay within bounds.
    late_rail_receipts = {}
    for label, field, content_field, receipt_label, nonce in (
        ("registry-index", "railRegistryIndexReceipt", "railRegistryIndex", "rail-index", "200"),
        ("rail-definition", "railDefinitionReceipt", "railDefinition", "rail-definition", "201"),
    ):
        data = base("aw-auth-complete-envelope")
        authority = data["authority"]
        started_at = authority["sessionContextSource"]["startedAt"]
        content = authority[content_field]
        authority[field] = registry_anchor_receipt(
            authority[field]["logicalAddress"], content,
            label=receipt_label, nonce=nonce, block_timestamp=started_at + 1,
        )
        if not (authority["railDefinition"]["governance"]["acceptedAt"] <= started_at):
            raise AssertionError("RTB-1 vector must keep acceptedAt within bounds")
        late_rail_receipts[label] = data

    # DACS-4 PC-1: the Atomic handler selects AtomicPaymentPhaseInputV1 before
    # reading fields; the ordinary arm, or a record carrying both arms'
    # session members, is not coerced into it.
    def ordinary_arm(payment_input: dict[str, Any]) -> None:
        payment_input["sessionContext"] = payment_input.pop("atomicSessionContext")

    def both_arms(payment_input: dict[str, Any]) -> None:
        payment_input["sessionContext"] = copy.deepcopy(payment_input["atomicSessionContext"])

    def payment_input_arm(edit) -> dict[str, Any]:
        data = base("aw-auth-complete-envelope")
        edit(data["authority"]["paymentPhaseInput"])
        return data

    cross_context = (
        ("network", "networkId", "demos:othernet"),
        ("session", "jobId", "01K1DPA0000000000000000009"),
        ("phase", "phaseIndex", 7),
        ("rail", "railId", "demos-native:OTHER"),
        ("operation-index", "operationIndex", 4),
        ("role", "role", "orchestrator"),
        ("version", "authorizationVersion", "2"),
        ("job-id-first-character-8", "jobId", JOB_ID_FIRST_8),
    )
    authorizations_absent = base("aw-auth-complete-envelope")
    del authorizations_absent["authorizations"]
    authorization = [
        vector("aw-auth-authorizations-unavailable", ["AW-34"], "authorization", authorizations_absent, "indeterminate", "Without the operation authorizations the verifier cannot verify any required role; unavailable authority is indeterminate, not a crash."),
        vector("aw-auth-validly-signed-for-another-work", ["AW-31", "AW-36"], "authorization", resigned_authorization(lambda e: e.update(workId=ref.work_id(other_work))), "fail", "The payer's valid signature over a Work that differs only in expiresAt does not authorize this Work."),
        vector("aw-auth-orchestrator-signs-as-payer", ["AW-33", "AW-38"], "authorization", resigned_authorization(lambda e: e.update(signer=CLAIMS["orchestrator"]), "orchestrator"), "fail", "A valid orchestrator signature on the payer's payment authorization does not become payer authority."),
        *(
            vector(f"aw-auth-validly-signed-other-{label}", ["AW-36"], "authorization", resigned_authorization(lambda e, f=field, v=value: e.update({f: v})), "fail", f"A valid payer signature binding another {field} cannot be replayed into this context.")
            for label, field, value in cross_context
        ),
        *(
            vector(f"aw-auth-rail-{label}-receipt-after-session", ["AW-33"], "authorization", input_value, "fail", f"DACS-4 RTB-1: with acceptedAt and the other receipt in bounds, a finalized {label} receipt later than session start cannot authorize the rail.")
            for label, input_value in late_rail_receipts.items()
        ),
        vector("aw-auth-roster-payer-account-not-bundle-derived", ["AW-33"], "authorization", roster_account("payer", "dem-not-the-payer"), "fail", "A roster payer nativeAccount that the payer IdentityBundle does not derive is not payment authority."),
        vector("aw-auth-roster-seller-account-not-bundle-derived", ["AW-33"], "authorization", roster_account("seller", "dem-not-the-seller"), "fail", "A roster seller nativeAccount that the seller IdentityBundle does not derive is not payee authority."),
        vector("aw-auth-pc1-ordinary-arm-not-coerced", ["AW-7", "AW-33"], "authorization", payment_input_arm(ordinary_arm), "fail", "DACS-4 PC-1: an ordinary PaymentPhaseInput (sessionContext) given to the Atomic handler is not renamed into AtomicPaymentPhaseInputV1."),
        vector("aw-auth-pc1-both-arm-members", ["AW-7", "AW-33"], "authorization", payment_input_arm(both_arms), "fail", "DACS-4 PC-1: a payment input carrying both sessionContext and atomicSessionContext is neither closed arm, and no member is dropped to select one."),
    ]

    # ---- execution: receipt, attempts, limits, projection ---------------------
    def receipt_variant(edit, *, root: bool = True) -> dict[str, Any]:
        data = base("aw-receipt-complete-and-final")
        edit(data["receipt"])
        if root:
            recompute_root(data["receipt"])
        data["receipt"] = rebind_receipt_finality(data["receipt"])
        return data

    def other_receipt(data_edit) -> dict[str, Any]:
        data = base("aw-receipt-complete-and-final")
        data_edit(data)
        return data

    def other_work_receipt(data):
        other = copy.deepcopy(data["intent"])
        other["expiresAt"] -= 1
        data["receipt"] = final_receipt(other)

    def storage_output_differs(receipt):
        leaf = receipt["operationResults"][3]
        leaf["storageOutput"]["logicalAddress"] = "dacs3:commit:01K1DPA0000000000000000009"
        leaf["outputHash"] = ref.sha256_hex(ref.jcs_bytes(leaf["storageOutput"]))

    def checkpoint_by_buyer(data):
        finality = json.loads(ref.b64u_decode(data["receipt"]["finalityEvidence"]["value"]))
        finality.pop("signature", None)
        data["receipt"]["finalityEvidence"] = encoded_evidence(
            "test-bft-checkpoint", finality, "buyer", ref._CHECKPOINT_TEST_DOMAIN)

    def rollback_variant(edit, *, root: bool = False) -> dict[str, Any]:
        data = base("aw-rollback-proves-unchanged")
        edit(data)
        if root:
            recompute_root(data["receipt"])
        data["receipt"] = rebind_receipt_finality(data["receipt"])
        return data

    def leak_state(data):
        def leak(witness):
            witness["postState"] = {"balances": {"payer": "90", "seller": "10"}, "artifacts": []}
        resign_state_witness(data["receipt"], leak)

    def later_marked_rolled_back(data):
        ids = [op["operationId"] for op in data["intent"]["operations"]]
        for result in data["receipt"]["operationResults"][ids.index(data["receipt"]["failedOperationId"]) + 1:]:
            result["status"] = "rolled-back"

    def slot_side(side, field, value):
        def edit(receipt):
            receipt["paymentSlot"][side][field] = value
        return edit

    def not_copied(receipt):
        for side in ("before", "after"):
            receipt["paymentSlot"][side]["receiptCommitment"] = "6f" * 32
            receipt["paymentSlot"][side]["workId"] = "6e" * 32

    def advance_after(receipt):
        receipt["paymentSlot"]["after"]["generation"] += 1

    other_purchase = completion_receipt_input()
    other_purchase["purchaseIntent"]["expiresAt"] -= 1
    other_purchase["purchaseReceipt"] = final_receipt(other_purchase["purchaseIntent"])
    other_job = purchase_intent()
    other_job_receipt = final_receipt(other_job)
    other_job_completion = completion_intent(other_job_receipt, job_id="01K1DPA0000000000000000009")
    rolled_back_purchase = purchase_intent()
    rolled_back_purchase_receipt = final_receipt(rolled_back_purchase, "rolled-back", 5)
    after_rollback = completion_intent(rolled_back_purchase_receipt)
    after_rollback_receipt = final_receipt(after_rollback)
    settled_slot = copy.deepcopy(final_receipt(purchase_intent())["paymentSlot"]["after"])
    after_rollback_receipt["paymentSlot"]["before"] = copy.deepcopy(settled_slot)
    after_rollback_receipt["paymentSlot"]["after"] = copy.deepcopy(settled_slot)
    after_rollback_receipt = rebind_receipt_finality(after_rollback_receipt)

    def rolled_back_completion(edit=None) -> dict[str, Any]:
        def unchanged(receipt):
            if edit is not None:
                edit(receipt)
        return completion_receipt_input(unchanged, outcome="rolled-back")

    def winner_inventory(data, attempts):
        data["ledgerInventory"] = effect_inventory(
            ref.work_id(data["intent"]),
            [(a["attemptId"], a["nativeTransactionRef"]) for a in attempts],
            block_id=attempts[0]["lifecycleEvidence"]["blockId"],
        )
        return data

    changed_bytes = base("aw-attempt-changed-bytes")
    winner_inventory(changed_bytes, changed_bytes["attempts"])
    two_included = base("aw-two-included-attempts")
    winner_inventory(two_included, two_included["attempts"][:1])
    replaced_included = base("aw-replacement-with-noninclusion")
    replaced_work = ref.work_id(replaced_included["intent"])
    prior = next(a for a in replaced_included["attempts"] if a["attemptClass"] != "replacement")
    replacement = next(a for a in replaced_included["attempts"] if a["attemptClass"] == "replacement")
    prior["lifecycleEvidence"] = ledger_evidence(
        prior["attemptId"], replaced_work, "included-committed", prior["nativeTransactionRef"])
    replacement.pop("lifecycleEvidence", None)
    replaced_included["winningAttemptId"] = prior["attemptId"]
    winner_inventory(replaced_included, [prior])
    replaced_included.pop("receipt", None)
    other_attempt_evidence = base("aw-single-ledger-winner")
    winner = next(a for a in other_attempt_evidence["attempts"] if a["attemptId"] == other_attempt_evidence["winningAttemptId"])
    winner["lifecycleEvidence"] = ledger_evidence(
        "attempt-x", ref.work_id(other_attempt_evidence["intent"]), winner["lifecycleEvidence"]["state"],
        winner["nativeTransactionRef"], nonce=winner["lifecycleEvidence"]["nonce"],
        fee=winner["lifecycleEvidence"]["fee"])
    other_winner = base("aw-exact-replay-returns-winner")
    next(a for a in other_winner["attempts"] if a["attemptClass"] == "replay")["returnedWinner"] = "attempt-x"
    duplicate_attempt = base("aw-single-ledger-winner")
    twin = copy.deepcopy(next(a for a in duplicate_attempt["attempts"] if a["attemptId"] == duplicate_attempt["winningAttemptId"]))
    twin.pop("lifecycleEvidence", None)
    twin["nativeTransactionRef"] = {"kind": "demos-transaction", "value": "tx-twin"}
    duplicate_attempt["attempts"].append(twin)
    attempt_version_two = base("aw-single-ledger-winner")
    next(a for a in attempt_version_two["attempts"] if a["attemptId"] == attempt_version_two["winningAttemptId"])["attemptVersion"] = "2"

    def limit_over(name: str, field: str) -> dict[str, Any]:
        data = base(name)
        return resign_capability_limit(data, field, data["capability"]["limits"][field] - 1)

    def projection_variant(edit_resolved=None, path_index=None) -> dict[str, Any]:
        data = base("aw-anchor-projection")
        anchor = data["anchorReceipt"]
        resolved = json.loads(ref.b64u_decode(anchor["evidence"]["value"]))
        if path_index is not None:
            path = ref.inclusion_path(data["receipt"]["operationResults"], path_index)
            data["operationEvidence"]["inclusionPath"] = path
            resolved["inclusionPath"] = path
        if edit_resolved is not None:
            edit_resolved(resolved)
        anchor["evidence"]["value"] = ref.b64u(ref.jcs_bytes(resolved))
        return data

    projection_index = by_name["aw-anchor-projection"]["input"]["operationEvidence"]["leaf"]["operationIndex"]
    projection_anchor_version_two = base("aw-anchor-projection")
    projection_anchor_version_two["anchorReceipt"]["receiptVersion"] = "2"
    receipt_network = base("aw-receipt-complete-and-final")
    network_cap = {k: v for k, v in receipt_network["capability"].items() if k != "evidence"}
    network_cap["networkId"] = "demos:othernet"
    receipt_network["capability"] = sign_capability(network_cap)
    # The signed slot key names the next phase; the receipt is finalized for
    # exactly that Work, so only the slot-key/intent tuple check differs.
    slot_tuple_intent = purchase_intent()
    slot_tuple_intent["operations"][4]["payload"]["slotKey"]["phaseIndex"] = slot_tuple_intent["phaseIndex"] + 1
    slot_tuple_receipt = base("aw-receipt-complete-and-final")
    slot_tuple_receipt.update(intent=slot_tuple_intent, receipt=final_receipt(slot_tuple_intent))

    execution = [
        vector("aw-receipt-of-another-work", ["AW-46"], "receipt", other_receipt(other_work_receipt), "fail", "A complete, finalized receipt for a Work differing only in expiresAt does not bind this Work."),
        vector("aw-receipt-execution-profile-differs", ["AW-46"], "receipt", receipt_variant(lambda r: r.update(executionProfile="demos-bft-work/2"), root=False), "fail", "A re-finalized receipt naming another executionProfile does not bind the signed Work."),
        vector("aw-receipt-results-count-short", ["AW-46", "AW-51"], "receipt", receipt_variant(lambda r: r["operationResults"].pop()), "fail", "A receipt with one operation result fewer than the Work, under a recomputed root and checkpoint, is rejected."),
        vector("aw-receipt-operation-identity-swapped", ["AW-46", "AW-51"], "receipt", receipt_variant(lambda r: r["operationResults"][0].update(operationId="buyer-vet-x")), "fail", "Each operation result names its Work operation's id, index and kind, under a recomputed root."),
        vector("aw-receipt-input-hash-consistent-mismatch", ["AW-46", "AW-51"], "receipt", receipt_variant(lambda r: r["operationResults"][2].update(inputHash="ab" * 32)), "fail", "A verifier recomputes every inputHash; a re-rooted, re-finalized receipt with a wrong one is rejected."),
        vector("aw-receipt-output-hash-consistent-mismatch", ["AW-46", "AW-51"], "receipt", receipt_variant(lambda r: r["operationResults"][5].update(outputHash="ef" * 32)), "fail", "A re-rooted, re-finalized receipt whose transfer outputHash contradicts the signed payload is rejected."),
        vector("aw-receipt-root-claim-consistent-mismatch", ["AW-46", "AW-51"], "receipt", receipt_variant(lambda r: r.update(operationReceiptRoot="cd" * 32), root=False), "fail", "A finalized checkpoint over a wrong operationReceiptRoot does not make that root the RFC 6962 root of the results."),
        vector("aw-receipt-pre-root-consistent-mismatch", ["AW-46", "AW-48"], "receipt", receipt_variant(lambda r: r["businessState"].update(preRoot="12" * 32), root=False), "fail", "The business pre-state root is recomputed from the authenticated witness, not taken from the finalized receipt."),
        vector("aw-receipt-effects-root-consistent-mismatch", ["AW-46", "AW-48"], "receipt", receipt_variant(lambda r: r["businessState"].update(effectsRoot="34" * 32), root=False), "fail", "The effects root is recomputed from the authenticated witness, not taken from the finalized receipt."),
        vector("aw-receipt-slot-key-other-phase", ["AW-46", "AW-50"], "receipt", receipt_variant(lambda r: r["paymentSlot"]["key"].update(phaseIndex=7), root=False), "fail", "A re-finalized receipt whose slot key names another phase does not bind the signed slot."),
        vector("aw-receipt-field-changed-after-commitment", ["AW-46", "AW-50"], "receipt", other_receipt(lambda d: d["receipt"]["winningAttempt"].update(attemptId="attempt-z")), "fail", "A receipt member edited after its receiptCommitment was computed no longer matches the canonical receipt core."),
        vector("aw-receipt-storage-output-address-differs", ["AW-46", "AW-51"], "receipt", receipt_variant(storage_output_differs), "fail", "A storageOutput naming another address, with a consistent outputHash and root, contradicts the signed storage payload."),
        vector("aw-receipt-checkpoint-signed-by-buyer", ["AW-47", "AW-48"], "receipt", other_receipt(checkpoint_by_buyer), "fail", "A finality checkpoint is authenticated only by the pinned network authority; a party-signed checkpoint is not finality."),
        vector("aw-receipt-capability-other-network", ["AW-20", "AW-46"], "receipt", receipt_network, "fail", "A receipt is verified only under a capability for its own networkId."),
        vector("aw-receipt-slot-job-id-first-character-8", ["AW-46", "AW-50"], "receipt", receipt_variant(lambda r: r["paymentSlot"]["key"].update(jobId=JOB_ID_FIRST_8), root=False), "fail", "A re-finalized receipt whose slot key jobId starts with 8 does not carry a canonical JID-1 jobId."),
        vector("aw-rolled-back-receipt-changes-business-state", ["AW-54", "AW-55"], "receipt", rollback_variant(leak_state), "fail", "A rolled-back receipt with a re-signed witness and consistent roots still cannot change business state."),
        vector("aw-rolled-back-later-operation-marked-rolled-back", ["AW-52", "AW-53"], "receipt", rollback_variant(later_marked_rolled_back, root=True), "fail", "Operations after the failed one are not-executed, not rolled-back, under a recomputed root."),
        vector("aw-rolled-back-slot-generation-advanced", ["AW-50", "AW-53"], "receipt", rollback_variant(lambda d: advance_after(d["receipt"])), "fail", "A rolled-back Purchase slot terminal state follows the signed CAS; an advanced generation contradicts it."),
        vector("aw-completion-receipt-control", ["AW-46", "AW-50"], "receipt", completion_receipt_input(), "pass", "A Completion receipt copies the verified Purchase receipt's settled slot state unchanged."),
        vector("aw-completion-receipt-slot-after-changed", ["AW-46", "AW-50"], "receipt", completion_receipt_input(advance_after), "fail", "A Completion cannot change the payment slot it inherits from the Purchase."),
        vector("aw-completion-slot-not-copied-from-purchase", ["AW-46", "AW-50"], "receipt", completion_receipt_input(not_copied), "fail", "A Completion slot state that is unchanged (before == after) but is not the verified Purchase terminal state is rejected."),
        vector("aw-completion-embeds-other-purchase-receipt", ["AW-46"], "receipt", other_purchase, "fail", "The Completion's embedded Purchase receipt must be the independently verified Purchase receipt."),
        vector("aw-completion-receipt-for-other-job", ["AW-46"], "receipt", {"intent": other_job_completion, "receipt": final_receipt(other_job_completion), "purchaseIntent": other_job, "purchaseReceipt": other_job_receipt, "publicKeys": PUBLIC_KEYS}, "fail", "A Completion for another jobId cannot reuse this Purchase receipt."),
        vector("aw-completion-after-rolled-back-purchase", ["AW-46"], "receipt", {"intent": after_rollback, "receipt": after_rollback_receipt, "purchaseIntent": rolled_back_purchase, "purchaseReceipt": rolled_back_purchase_receipt, "publicKeys": PUBLIC_KEYS}, "fail", "A Completion after a rolled-back Purchase has no committed payment to complete."),
        vector("aw-completion-rolled-back-control", ["AW-52", "AW-53"], "receipt", rolled_back_completion(), "pass", "A rolled-back Completion leaves business state and the Purchase slot unchanged."),
        vector("aw-completion-rolled-back-slot-changed", ["AW-50", "AW-53"], "receipt", rolled_back_completion(advance_after), "fail", "A rolled-back Completion cannot change the Purchase slot metadata."),
        vector("aw-attempt-changed-bytes-inventory-consistent", ["AW-39"], "attempts", changed_bytes, "fail", "An attempt whose canonicalWorkBytes differ is rejected even under a ledger inventory that names it."),
        vector("aw-two-included-attempts-inventory-names-one", ["AW-43"], "attempts", two_included, "fail", "Two included attempts are two winners even when the inventory names only one."),
        vector("aw-replacement-for-included-attempt", ["AW-41"], "attempts", replaced_included, "fail", "An attempt with authenticated inclusion cannot be replaced."),
        vector("aw-lifecycle-evidence-names-other-attempt", ["AW-59"], "attempts", other_attempt_evidence, "fail", "Network-signed lifecycle evidence for another attemptId does not establish this attempt's inclusion."),
        vector("aw-replay-returns-other-winner", ["AW-45"], "attempts", other_winner, "fail", "An exact replay returns the ledger-selected winner and no other attempt."),
        vector("aw-attempts-duplicate-attempt-id", ["AW-40"], "attempts", duplicate_attempt, "fail", "Two attempts cannot share one attemptId."),
        vector("aw-attempt-version-unsupported", ["AW-39"], "attempts", attempt_version_two, "fail", "An attempt with attemptVersion 2 is not AtomicWorkAttemptV1."),
        vector("aw-canonical-byte-limit-one-over", ["AW-71"], "limits", limit_over("aw-canonical-byte-limit-equality", "maxCanonicalBytes"), "fail", "A Work one canonical byte over the authenticated limit is rejected.", boundary=True),
        vector("aw-operation-count-limit-one-over", ["AW-71"], "limits", limit_over("aw-operation-count-limit-equality", "maxOperations"), "fail", "A Work one operation over the authenticated limit is rejected.", boundary=True),
        vector("aw-execution-time-limit-one-over", ["AW-71"], "limits", limit_over("aw-execution-time-limit-equality", "maxExecutionTimeMs"), "fail", "A Work one millisecond over the authenticated execution-time limit is rejected.", boundary=True),
        vector("aw-anchor-inclusion-path-consistent-invalid", ["AW-68", "AW-69"], "projection", projection_variant(path_index=0 if projection_index != 0 else 1), "fail", "A projection whose copied and resolved inclusion paths agree but prove another leaf is rejected."),
        vector("aw-anchor-resolved-receipt-hash-differs", ["AW-68", "AW-69"], "projection", projection_variant(lambda r: r.update(receiptContentHash="00" * 32)), "fail", "Resolved projection evidence for another receipt does not resolve the verified Work receipt."),
        vector("aw-receipt-version-unsupported", ["AW-46"], "receipt", receipt_variant(lambda r: r.update(receiptVersion="2"), root=False), "fail", "A re-finalized receipt with receiptVersion 2 is not AtomicWorkReceiptV1."),
        vector("aw-receipt-signed-slot-tuple-differs", ["AW-46", "AW-50"], "receipt", slot_tuple_receipt, "fail", "A finalized receipt for a Purchase whose signed slot key names another phase than its intent tuple does not bind the payment slot."),
        vector("aw-anchor-projection-receipt-version-unsupported", ["AW-66"], "projection", projection_anchor_version_two, "fail", "A projected AnchorReceipt with receiptVersion 2 is not the CORE §5.1 AnchorReceipt the verified Work receipt projects."),
    ]

    # ---- Purchase and Completion admission ------------------------------------
    def listing_edit(edit, role: str = "seller"):
        return ("listing_fixture", resigned_builder(resign_listing_as(role), edit))

    def agreement_edit(edit):
        return ("agreement_document", resigned_builder(resign_payee_agreement, edit))

    def embedded_edit(name: str, edit, role: str, domain: bytes):
        return (name, resigned_builder(resign_embedded_as(role, domain), edit))

    def registry_edit(edit):
        def wrap(real):
            def fake(rail):
                index, _, rail_receipt = real(rail)
                edit(index)
                return index, registry_anchor_receipt(
                    index["logicalAddress"], index, label="rail-index", nonce="200",
                ), rail_receipt
            return fake
        return ("rail_registry_material", wrap)

    def drop_roles(index):
        def transform(intent):
            intent["operations"][index]["requiredRoles"] = []
        return transform

    def bad_bundle_presentation(value):
        value["authority"]["payerBundle"]["presentation"]["signatures"][0]["signature"] = ref.b64u(b"\x01" * 64)

    def sequential_receipt_other_content(value):
        receipt = value["authority"]["commitmentReceipt"]
        receipt["contentHash"] = "00" * 32
        proof = json.loads(ref.b64u_decode(receipt["evidence"]["value"]))
        proof.pop("signature", None)
        proof["contentHash"] = "00" * 32
        receipt["evidence"] = encoded_evidence("test-anchor-finality", proof, "network", ref._ANCHOR_TEST_DOMAIN)

    def commitment_anchored_at(timestamp: int):
        # Move only the commitment AnchorReceipt's consensus time and re-sign
        # its finality proof; the Work receipt stays at 1_800_000_030_000.
        def wrap(real):
            def fake(record):
                receipt = real(record)
                receipt["blockRef"]["timestamp"] = timestamp
                proof = json.loads(ref.b64u_decode(receipt["evidence"]["value"]))
                proof.pop("signature", None)
                proof["blockRef"] = copy.deepcopy(receipt["blockRef"])
                receipt["evidence"] = encoded_evidence("test-anchor-finality", proof, "network", ref._ANCHOR_TEST_DOMAIN)
                return receipt
            return fake
        return ("commitment_anchor_receipt", wrap)

    def sequential_anchor_variant(anchor_time: int, not_after: int | None = None):
        wraps = [commitment_anchored_at(anchor_time)]
        if not_after is not None:
            wraps.append(listing_edit(lambda l: l["validity"].update(notAfter=not_after)))
        return composed_variant(tuple(wraps), gate_mode="sequential")

    def session_evidence(value, session):
        value["authority"]["atomicSessionContextEvidence"] = encoded_evidence(
            "test-atomic-session-context",
            {"jobId": value["intent"]["jobId"], "contextHash": ref.sha256_hex(ref.jcs_bytes(session)),
             "proofProfile": "demos-bft-proof/test-1"},
            "orchestrator", ref._SESSION_CONTEXT_TEST_DOMAIN)

    def session_version_two(value):
        session = value["authority"]["atomicSessionContext"]
        session["contextVersion"] = "2"
        value["authority"]["paymentPhaseInput"]["atomicSessionContext"] = copy.deepcopy(session)
        session_evidence(value, session)

    def session_source_differs(value):
        authority = value["authority"]
        authority["sessionContextSource"]["priorPhaseOutputs"]["agreementHash"] = "0f" * 32
        rebind_session_source_evidence(authority)
        session = atomic_payment_session_context_from_source(authority["sessionContextSource"])
        authority["atomicSessionContext"] = session
        authority["paymentPhaseInput"]["atomicSessionContext"] = copy.deepcopy(session)
        session_evidence(value, session)

    def session_evidence_other(value):
        value["authority"]["atomicSessionContextEvidence"] = encoded_evidence(
            "test-atomic-session-context",
            {"jobId": value["intent"]["jobId"], "contextHash": "3c" * 32,
             "proofProfile": "demos-bft-proof/test-1"},
            "orchestrator", ref._SESSION_CONTEXT_TEST_DOMAIN)

    def capability_limit(field: str, measure):
        def edit(value):
            cap = {k: v for k, v in value["capability"].items() if k != "evidence"}
            cap["limits"][field] = measure(value) - 1
            value["capability"] = sign_capability(cap)
        return edit

    def metrics_other_work(value):
        material = ref.composed_proof_material(value)
        metrics = json.loads(ref.b64u_decode(limit_metrics_evidence(value, material, 100)["value"]))
        metrics.pop("signature", None)
        metrics["workId"] = "4d" * 32
        value["limitEvidence"] = encoded_evidence("test-work-limit-metrics", metrics, "network", ref._LIMITS_TEST_DOMAIN)

    def reservation_other_work(value):
        cap = value["capability"]
        value["proofReservationEvidence"] = encoded_evidence(
            "test-work-proof-reservation",
            {"workId": "4e" * 32, "reservedProofBytes": value["proofReservationBytes"],
             "reservationRule": "test-fixed-proof-reservation/1",
             "proofProfile": cap["proofProfile"], "validatorSetId": cap["validatorSetId"]},
            "network", ref._LIMITS_TEST_DOMAIN)
        value["limitEvidence"] = limit_metrics_evidence(value, ref.composed_proof_material(value), 100)

    def payment_amount_differs(value):
        value["authority"]["paymentPhaseInput"]["amount"] = {"amount": "11", "currency": "DEM"}

    def payer_bundle_version_two(real):
        def fake(role, *args, **kwargs):
            bundle = real(role, *args, **kwargs)
            if role != "buyer":
                return bundle
            # The buyer's bundle carries the payer claim, so it is the payer
            # bundle; re-present it so only bundleVersion is wrong.
            bundle.pop("presentation")
            bundle["bundleVersion"] = "2"
            digest = ref.sha256_hex(ref.jcs_bytes(bundle))
            bundle["presentation"] = {"kind": "per-claim", "signatures": [{
                "ref": CLAIMS[role],
                "signature": ref.b64u(ref.ed25519_sign(
                    SEEDS[role], b"dacs-bundle-presentation:v1:" + digest.encode("ascii"))),
            }]}
            return bundle
        return fake

    def payee_bound_with_current_admission() -> dict[str, Any]:
        def revocation(listing):
            listing["revocationState"] = {
                "revocationStateRefVersion": "1",
                "anchor": {"kind": "storage-program",
                           "locator": f"dacs1-revocations:{ref.cf4_encode(CLAIMS['seller'])}"},
                "contentHash": ref.sha256_hex(ref.jcs_bytes({"seller": CLAIMS["seller"], "sequence": 7})),
            }
        name, wrap = listing_edit(revocation)
        with patched_builder(name, wrap):
            intent = purchase_intent(payee_bound=True)
            value = composed_purchase_admission(intent, final_receipt(intent))
            value["authority"]["currentProfileAdmission"] = current_profile_admission(intent, value["authority"])
        return add_composed_limit_evidence(value)

    def completion_variant(*, delivery_roles=None, projection_index=None, slot_commitment=None) -> dict[str, Any]:
        purchase_value = purchase_intent(current_profile=True)
        purchase_receipt = final_receipt(purchase_value)
        completion_value = completion_intent(purchase_receipt)
        if delivery_roles is not None:
            completion_value["operations"][1]["requiredRoles"] = delivery_roles
        receipt = final_receipt(completion_value)
        if slot_commitment is not None:
            for side in ("before", "after"):
                receipt["paymentSlot"][side]["receiptCommitment"] = slot_commitment
            receipt = rebind_receipt_finality(receipt)
        value = composed_completion_admission(purchase_value, purchase_receipt, completion_value, receipt)
        if projection_index is not None:
            value["purchaseCommitmentProjection"] = projected_anchor_fixture(purchase_value, purchase_receipt, projection_index)
            value = add_composed_limit_evidence(value)
        return value

    def profile_variant(index: int, edit) -> dict[str, Any]:
        data = base("awp-purchase-exact-profile")
        edit(data["intent"]["operations"][index]["payload"])
        data["atomicReceipt"] = final_receipt(data["intent"])
        return data

    def vet_address(payload):
        payload["logicalAddress"] += "x"

    def commitment_address(payload):
        payload["logicalAddress"] = "dacs3:commit:01K1DPA0000000000000000001"

    def commitment_cas(payload):
        payload["writeCondition"] = {"kind": "compare-and-set", "expectedContentHash": "00" * 32}

    shape_kind = composed_with_intent(lambda i: i["operations"][2].update(kind="storage-program-put", payload={**i["operations"][2]["payload"], "logicalAddress": f"dacs3:agreement:{i['jobId']}", "writeCondition": {"kind": "create-only"}}))
    shape_depends = composed_with_intent(lambda i: i["operations"][3].update(dependsOn=["buyer-vet", "agreement"]))
    two_pay_dem = composed_variant(
        (listing_edit(lambda l: l["pipeline"].append({"kind": "pay-dem", "parameters": {"rail": TEST_RAIL_ID}})),),
        payout_bindings=[
            {"railId": TEST_RAIL_ID, "phaseIndex": 2, "payeeAddress": "dem-test-seller"},
            {"railId": TEST_RAIL_ID, "phaseIndex": 4, "payeeAddress": "dem-test-seller"},
        ],
    )
    # The intent and its signed slot key name the next phase consistently and
    # the receipt is finalized for that Work; only the Listing's pay-dem
    # phase tuple differs.
    pay_dem_tuple = base("awp-purchase-exact-profile")
    pay_dem_tuple["intent"]["phaseIndex"] += 1
    pay_dem_tuple["intent"]["operations"][4]["payload"]["slotKey"]["phaseIndex"] = pay_dem_tuple["intent"]["phaseIndex"]
    pay_dem_tuple["atomicReceipt"] = final_receipt(pay_dem_tuple["intent"])
    purchase_completion = [
        vector("awp-profile-pay-dem-tuple-differs", ["AWP-20"], "profile", pay_dem_tuple, "fail", "A Purchase whose intent names another phase than the signed Listing's pay-dem phase is rejected on the profile surface under its own consistent receipt."),
        vector("awp-composed-payment-required-roles-empty", ["AWP-5"], "purchase-admission", composed_with_intent(drop_roles(5)), "fail", "A re-signed Purchase whose payment step requires no payer authorization is not the exact Purchase profile."),
        vector("awp-composed-operation-kind-differs", ["AWP-5"], "purchase-admission", shape_kind, "fail", "A re-signed Purchase that stores the agreement instead of asserting it is not the exact Purchase profile, although its DAG and roles are valid."),
        vector("awp-composed-dependencies-differ", ["AWP-5"], "purchase-admission", shape_depends, "fail", "A re-signed Purchase whose commitment also depends on the buyer Vet is not the exact Purchase profile, although its DAG is valid."),
        vector("awp-completion-delivery-required-roles-empty", ["AWP-15"], "completion-admission", completion_variant(delivery_roles=[]), "fail", "A re-signed Completion whose delivery requires no seller authorization is not the exact Completion profile."),
        vector("awp-composed-agreement-price-differs-from-listing", ["AWP-7"], "purchase-admission", composed_variant((listing_edit(lambda l: l["pricing"]["price"].update(amount="9")),)), "fail", "A re-signed Listing whose fixed price differs from the Agreement fails §8.5.2."),
        vector("awp-composed-agreement-deliverable-hash-differs", ["AWP-7"], "purchase-admission", composed_variant((agreement_edit(lambda a: a["terms"]["deliverable"].update(hash="99" * 32)),)), "fail", "A re-signed Agreement whose deliverable differs from the Listing DeliverableSpec fails §8.5.2."),
        vector("awp-composed-deadline-exceeds-listing-bound", ["AWP-7", "AWP-8"], "purchase-admission", composed_variant((listing_edit(lambda l: l["terms"].update(deadlineSecAfterCommit=1)),)), "fail", "An Agreement deadline past the Listing's commitment-relative bound fails at consensus time."),
        vector("awp-composed-listing-expired-before-commit", ["AWP-7", "AWP-8"], "purchase-admission", composed_variant((listing_edit(lambda l: l["validity"].update(notAfter=1_800_000_000_000)),)), "fail", "A Listing whose notAfter precedes the authenticated commitment time cannot authorize the session."),
        vector("awp-sequential-deadline-at-anchor-bound", ["AWP-7", "AWP-8"], "purchase-admission", sequential_anchor_variant(1_800_000_000_000), "pass", "Under the sequential gate committedAt is the commitment AnchorReceipt time: an Agreement deadline exactly deadlineSecAfterCommit after it is within the bound.", boundary_rules=["AWP-8"]),
        vector("awp-sequential-deadline-past-anchor-bound", ["AWP-7", "AWP-8"], "purchase-admission", sequential_anchor_variant(1_799_999_999_999), "fail", "With the commitment anchored one millisecond earlier the same deadline exceeds the bound, although it is within the bound measured from the later Work receipt.", boundary_rules=["AWP-8"]),
        vector("awp-sequential-listing-not-after-at-anchor-time", ["AWP-7", "AWP-8"], "purchase-admission", sequential_anchor_variant(1_800_000_000_000, 1_800_000_000_000), "pass", "A Listing whose notAfter equals the commitment AnchorReceipt time had not expired at commitment, although it expired before the later Work receipt.", boundary_rules=["AWP-8"]),
        vector("awp-sequential-listing-expired-before-anchor", ["AWP-7", "AWP-8"], "purchase-admission", sequential_anchor_variant(1_800_000_000_000, 1_799_999_999_999), "fail", "A Listing whose notAfter is one millisecond before the commitment AnchorReceipt time expired before commitment.", boundary_rules=["AWP-8"]),
        vector("awp-composed-authorizations-unavailable", ["AWP-5"], "purchase-admission", composed_variant(edit=lambda v: v.pop("authorizations")), "indeterminate", "A composed Purchase presented without its operation authorizations lacks role authority; admission is indeterminate and permits no payment."),
        vector("awp-composed-listing-negotiation-pattern-differs", ["AWP-7"], "purchase-admission", composed_variant((listing_edit(lambda l: l["pipeline"].__setitem__(0, {"kind": "negotiate-rfq"})),)), "fail", "An Agreement pattern differing from the Listing pipeline fails §8.5.2."),
        vector("awp-composed-listing-commit-phase-differs", ["AWP-7"], "purchase-admission", composed_variant((listing_edit(lambda l: l["pipeline"].__setitem__(1, {"kind": "commit-payee-bound-agreement"})),)), "fail", "An Agreement artifact that mismatches the Listing's commitment phase fails §8.5.2."),
        vector("awp-composed-agreement-rail-not-accepted", ["AWP-7", "AWP-20"], "purchase-admission", composed_variant((listing_edit(lambda l: l.update(acceptedRails=[{"railId": "other-rail"}])),)), "fail", "An Agreement rail that the Listing does not accept fails §8.5.2."),
        vector("awp-composed-agreement-pins-other-listing-version", ["AWP-7"], "purchase-admission", composed_variant((agreement_edit(lambda a: a["listingRef"].update(version=2)),)), "fail", "A re-signed Agreement must pin the exact Listing presented."),
        vector("awp-composed-listing-signed-by-orchestrator", ["AWP-7"], "purchase-admission", composed_variant((listing_edit(lambda l: None, "orchestrator"),)), "fail", "A Listing validly signed by the orchestrator is not signed by the seller IdentityBundle."),
        vector("awp-composed-listing-dacs-version-2", ["AWP-7"], "purchase-admission", composed_variant((listing_edit(lambda l: l.update(dacsVersion="2")),)), "fail", "A re-signed Listing with an unsupported dacsVersion is malformed."),
        vector("awp-composed-two-pay-dem-phases", ["AWP-20"], "purchase-admission", two_pay_dem, "fail", "A pipeline with two pay-dem phases does not have exactly one Atomic payment."),
        vector("awp-composed-rail-phase-handler-not-pay-dem", ["AWP-20"], "purchase-admission", composed_variant((embedded_edit("rail_definition", lambda r: r.update(phaseHandler="pay-evm"), "network", ref._RAIL_DOMAIN),)), "fail", "A network-signed, registry-pinned native-DEM RailDefinition whose phaseHandler is not pay-dem is rejected."),
        vector("awp-composed-registry-index-version-differs", ["AWP-7"], "purchase-admission", composed_variant((registry_edit(lambda i: i.update(registryVersion=2)),)), "fail", "A finalized registry index with an unsupported registryVersion is not a pinned snapshot."),
        vector("awp-composed-registry-index-content-hash-differs", ["AWP-7"], "purchase-admission", composed_variant((registry_edit(lambda i: i["entries"][0]["versions"][0].update(contentHash="00" * 32)),)), "fail", "A finalized registry index that pins another rail content hash does not resolve the presented rail."),
        vector("awp-composed-payer-bundle-presentation-invalid", ["AWP-7"], "purchase-admission", composed_variant(edit=bad_bundle_presentation), "fail", "A payer IdentityBundle with an invalid presentation signature is not payer authority."),
        vector("awp-composed-agreement-discriminator-version-2", ["AWP-4"], "purchase-admission", composed_variant((agreement_edit(lambda a: a.update(identityBoundPayeeAgreementVersion="2")),)), "fail", "A re-signed Agreement with an unsupported discriminator version is not IdentityBoundPayeeAgreementV1."),
        vector("awp-composed-payee-bound-agreement-with-current-admission", ["AWP-4"], "purchase-admission", payee_bound_with_current_admission(), "fail", "A current Atomic payment requires the identity-bound payee agreement, not a legacy payee-bound one, even with a current-profile admission."),
        vector("awp-composed-commitment-version-2", ["AWP-6"], "purchase-admission", composed_variant((embedded_edit("finality_commitment", lambda r: r.update(finalityCommitmentVersion="2"), "orchestrator", ref._COMMITMENT_DOMAIN),)), "fail", "A re-signed FinalityCommitmentRecord with an unsupported version is not the commitment artifact."),
        vector("awp-composed-commitment-subject-other-job", ["AWP-6"], "purchase-admission", composed_variant((embedded_edit("finality_commitment", lambda r: r.update(jobId="01K1DPA0000000000000000009"), "orchestrator", ref._COMMITMENT_DOMAIN),)), "fail", "A re-signed commitment for another jobId does not bind this job, agreement and listing."),
        vector("awp-composed-vet-record-version-2", ["AWP-1"], "purchase-admission", composed_variant((embedded_edit("composite_verification_record", lambda r: r.update(recordVersion="2"), "orchestrator", ref._COMPOSITE_DOMAIN),)), "fail", "A re-signed Vet record with an unsupported recordVersion is not a CompositeVerificationRecord v1."),
        vector("awp-composed-vet-record-bundle-hash-differs", ["AWP-1"], "purchase-admission", composed_variant((embedded_edit("composite_verification_record", lambda r: r.update(bundleHash="00" * 32), "orchestrator", ref._COMPOSITE_DOMAIN),)), "fail", "A re-signed Vet record for another IdentityBundle does not vet this party."),
        vector("awp-composed-vet-record-decision-fail", ["AWP-1"], "purchase-admission", composed_variant((embedded_edit("composite_verification_record", lambda r: r.update(overallDecision="fail"), "orchestrator", ref._COMPOSITE_DOMAIN),)), "fail", "A re-signed Vet record whose overallDecision is fail does not establish a pass."),
        vector("awp-sequential-commitment-receipt-other-content", ["AWP-6"], "purchase-admission", composed_variant(edit=sequential_receipt_other_content, gate_mode="sequential"), "fail", "A finalized AnchorReceipt for other content does not establish the commitment before signing in sequential mode."),
        vector("awp-composed-session-context-version-2", ["AWP-7"], "purchase-admission", composed_variant(edit=session_version_two), "fail", "A re-attested session context with contextVersion 2 is not AtomicPaymentSessionContextV1."),
        vector("awp-composed-session-source-prior-agreement-differs", ["AWP-7"], "purchase-admission", composed_variant(edit=session_source_differs), "fail", "A re-attested SessionContext source whose prior agreement hash contradicts the verified Agreement is not DACS authority."),
        vector("awp-composed-session-evidence-for-other-context", ["AWP-7"], "purchase-admission", composed_variant(edit=session_evidence_other), "fail", "Session evidence attesting another context hash does not authenticate the presented session context."),
        vector("awp-composed-payment-input-amount-differs", ["AWP-20"], "purchase-admission", composed_variant(edit=payment_amount_differs), "fail", "An AtomicPaymentPhaseInputV1 amount that differs from the Agreement is not bound to the authenticated parties."),
        vector("awp-composed-canonical-bytes-over", ["AWP-5"], "purchase-admission", composed_variant(edit=capability_limit("maxCanonicalBytes", lambda v: len(ref.jcs_bytes(v["intent"]))), rebuild_limits=True), "fail", "A composed Work one byte over the authenticated canonical-byte limit is rejected."),
        vector("awp-composed-operation-count-over", ["AWP-5"], "purchase-admission", composed_variant(edit=capability_limit("maxOperations", lambda v: len(v["intent"]["operations"]))), "fail", "A composed Work one operation over the authenticated operation limit is rejected."),
        vector("awp-composed-limit-metrics-for-other-work", ["AWP-5"], "purchase-admission", composed_variant(edit=metrics_other_work, rebuild_limits=False), "fail", "Network-signed limit metrics for another Work do not measure this one."),
        vector("awp-composed-reservation-for-other-work", ["AWP-5"], "purchase-admission", composed_variant(edit=reservation_other_work, rebuild_limits=False), "fail", "A network-signed proof-byte reservation for another Work does not reserve this one."),
        vector("awp-profile-vet-address-consistent-receipt", ["AWP-2"], "profile", profile_variant(0, vet_address), "fail", "A Vet storage operation at another address is rejected under its own consistent receipt."),
        vector("awp-profile-commitment-address-consistent-receipt", ["AWP-6"], "profile", profile_variant(3, commitment_address), "fail", "A commitment write at another job's address is rejected under its own consistent receipt."),
        vector("awp-profile-commitment-cas-consistent-receipt", ["AWP-6"], "profile", profile_variant(3, commitment_cas), "fail", "A commitment written by compare-and-set rather than create-only is rejected under its own consistent receipt."),
        vector("awp-completion-commitment-projection-selects-buyer-vet", ["AWP-13"], "completion-admission", completion_variant(projection_index=0), "fail", "A valid Purchase projection of the buyer Vet operation is not the commitment projection."),
        vector("awp-completion-composed-slot-not-copied-from-purchase", ["AWP-13"], "completion-admission", completion_variant(slot_commitment="6f" * 32), "fail", "A whole-profile Completion whose unchanged slot state is not the verified Purchase terminal state is rejected."),
        vector("awp-composed-payer-bundle-version-2", ["AWP-7"], "purchase-admission", composed_variant((("identity_bundle", payer_bundle_version_two),)), "fail", "A re-presented payer IdentityBundle with an unsupported bundleVersion is not payer authority."),
        vector("awp-composed-pc1-ordinary-arm-not-coerced", ["AWP-20"], "purchase-admission", composed_variant(edit=lambda v: ordinary_arm(v["authority"]["paymentPhaseInput"])), "fail", "DACS-4 PC-1: whole-profile admission does not rename an ordinary PaymentPhaseInput into the Atomic arm."),
    ]

    # ---- settlement and slot -------------------------------------------------
    final_bound = base("aws-final-work-receipt-bound")
    delivery_bound = base("aws-delivery-evidence-address")
    failure_bound = base("aws-failure-work-receipt-bound")
    failure_payload = failure_bound["intent"]["operations"][failure_bound["evidence"]["operationRef"]["operationIndex"]]["payload"]

    def as_success(evidence):
        evidence["outcome"] = "success"
        evidence.pop("reason", None)
        evidence["paymentAmount"] = {"amount": failure_payload["amount"], "currency": failure_payload["asset"]}
        evidence["settlementFinality"] = {"model": "bft-final", "finalityObservedAt": evidence["observedAt"]}

    def as_failure(evidence):
        evidence["outcome"] = "failure"
        evidence["reason"] = "claimed failure"
        evidence.pop("paymentAmount", None)
        evidence.pop("settlementFinality", None)

    def other_leaf_path(evidence):
        evidence["operationProof"]["value"] = ref.b64u(ref.jcs_bytes(
            ref.inclusion_path(final_bound["receipt"]["operationResults"], 4)))

    algorithm_label = copy.deepcopy(final_bound)
    algorithm_label["evidence"]["signature"]["algorithm"] = "ecdsa-secp256k1"
    algorithm_label["auditPublication"] = atomic_publication(algorithm_label["evidence"], algorithm_label["evidenceAddress"])
    other_generation = copy.deepcopy(final_bound)
    other_generation["evidenceAddress"] = ref.atomic_evidence_address(
        other_generation["evidence"], other_generation["receipt"]["paymentSlot"]["after"]["generation"] + 1)
    other_generation["auditPublication"] = atomic_publication(other_generation["evidence"], other_generation["evidenceAddress"])
    replay_contradiction = base("aws-atomic-publication-exact-replay")
    replay_anchor = replay_contradiction["auditPublication"]["anchorReceipt"]
    replay_proof = json.loads(ref.b64u_decode(replay_anchor["evidence"]["value"]))
    replay_proof.pop("signature", None)
    replay_proof["writeConditionResult"]["priorState"]["contentHash"] = "5a" * 32
    replay_anchor["evidence"] = encoded_evidence("test-anchor-publication", replay_proof, "network", ref._PUBLICATION_TEST_DOMAIN)

    def address_variant(address: str) -> dict[str, Any]:
        data = copy.deepcopy(final_bound)
        data["evidenceAddress"] = address
        data["auditPublication"] = atomic_publication(data["evidence"], address)
        return data

    # dacs4:payment:{jobId}:{rail}:{phaseIndex}:atomic:{generation}:{id}
    address_parts = final_bound["evidenceAddress"].split(":")

    def address_with(index: int, segment: str) -> str:
        return ":".join([*address_parts[:index], segment, *address_parts[index + 1:]])

    malformed_addresses = {
        "job-id-not-ulid": address_with(2, "not-a-ulid"),
        "job-id-first-character-8": address_with(2, "8" + address_parts[2][1:]),
        "rail-cf4-lowercase-escape": address_with(3, address_parts[3].replace("%3A", "%3a")),
        "phase-index-noncanonical": address_with(4, "0" + address_parts[4]),
        "phase-index-unsafe": address_with(4, str(ref.SAFE_INT_MAX + 1)),
        "atomic-label-missing": address_with(5, "legacy"),
        "generation-noncanonical": address_with(6, "0" + address_parts[6]),
        "settlement-id-uppercase": address_with(7, address_parts[7].upper()),
        "segment-count": ":".join(address_parts[:-1]),
    }
    slot_claim_advanced = base("aws-structured-network-slot-cas")
    slot_claim_advanced["newState"]["generation"] += 1
    inflight_other = base("aws-inflight-exact-replay")
    inflight_proof = {k: v for k, v in inflight_other["ledgerProof"].items() if k != "signature"}
    inflight_proof["state"]["workId"] = "77" * 32
    inflight_other["ledgerProof"] = resign_ledger_proof(inflight_proof)
    settled_other = base("aws-settled-exact-replay")
    settled_other["returnedReceiptCommitment"] = "66" * 32
    replay_transfer = base("aws-inflight-exact-replay")
    replay_transfer["executesTransfer"] = True
    job_id_8_slot = base("aws-structured-network-slot-cas")
    job_id_8_slot["key"]["jobId"] = JOB_ID_FIRST_8
    publication_version_two = copy.deepcopy(final_bound)
    publication_version_two["auditPublication"]["anchorReceipt"]["receiptVersion"] = "2"
    settlement_network = copy.deepcopy(final_bound)
    settlement_cap = {k: v for k, v in settlement_network["capability"].items() if k != "evidence"}
    settlement_cap["networkId"] = "demos:othernet"
    settlement_network["capability"] = sign_capability(settlement_cap)

    settlement = [
        vector("aws-atomic-evidence-version-unsupported", ["AWS-17"], "settlement", resettled(final_bound, lambda e: e.update(atomicEvidenceVersion="2")), "fail", "Re-signed, republished Atomic evidence with atomicEvidenceVersion 2 is rejected; it is not read as v1.", boundary_rules=["AWS-17"]),
        vector("aws-settlement-job-id-first-character-8", ["AWS-25"], "settlement", resettled(final_bound, lambda e: e.update(jobId="8" + e["jobId"][1:]), recompute_id=True), "fail", "Re-signed Atomic evidence whose jobId starts with 8 is not a canonical JID-1 session."),
        vector("aws-settlement-payment-amount-differs", ["AWS-24"], "settlement", resettled(final_bound, lambda e: e["paymentAmount"].update(amount="11")), "fail", "Re-signed evidence whose paymentAmount differs from the signed transfer is rejected."),
        vector("aws-settlement-signed-by-buyer-not-orchestrator", ["AWS-27"], "settlement", resettled(final_bound, lambda e: None, role="buyer"), "fail", "Evidence validly signed by the buyer is not signed by the authenticated phase orchestrator."),
        vector("aws-settlement-receipt-ref-content-hash-differs", ["AWS-19"], "settlement", resettled(final_bound, lambda e: e["workReceiptRef"].update(contentHash="aa" * 32)), "fail", "A re-signed workReceiptRef for other receipt bytes does not resolve the verified receipt."),
        vector("aws-settlement-operation-ref-differs-from-subject", ["AWS-20"], "settlement", resettled(final_bound, lambda e: e["operationRef"].update(operationId="payment-alt"), recompute_id=True), "fail", "A re-signed operationRef that differs from the proof subject's operation is rejected."),
        vector("aws-settlement-subject-winner-differs", ["AWS-19"], "settlement", resettled(final_bound, lambda e: e["operationProof"]["subject"].update(winningAttemptId="attempt-z")), "fail", "A re-signed proof subject naming another winner does not match the receipt."),
        vector("aws-settlement-inclusion-path-for-other-leaf", ["AWS-19"], "settlement", resettled(final_bound, other_leaf_path), "fail", "A re-signed inclusion path for another leaf does not prove the payment leaf."),
        vector("aws-settlement-success-on-rolled-back-receipt", ["AWS-20"], "settlement", resettled(failure_bound, as_success), "fail", "Re-signed success evidence over a rolled-back receipt does not select a committed operation."),
        vector("aws-settlement-failure-on-committed-receipt", ["AWS-20"], "settlement", resettled(final_bound, as_failure), "fail", "Re-signed failure evidence over a committed receipt does not select a rollback operation."),
        vector("aws-settlement-delivery-content-hash-differs", ["AWS-25"], "settlement", resettled(delivery_bound, lambda e: e.update(deliverableContentHash="bb" * 32)), "fail", "Re-signed delivery evidence with another content hash is rejected."),
        vector("aws-settlement-delivery-anchor-differs", ["AWS-25"], "settlement", resettled(delivery_bound, lambda e: e["deliverableAnchor"].update(locator="dacs4:deliverable:01K1DPA0000000000000000001")), "fail", "Re-signed delivery evidence anchored at another job's deliverable is rejected."),
        vector("aws-settlement-signature-algorithm-label", ["AWS-27"], "settlement", algorithm_label, "fail", "An Ed25519 signature relabelled as another algorithm is unsupported, under a matching publication."),
        vector("aws-settlement-address-other-generation", ["AWS-28"], "settlement", other_generation, "fail", "Evidence published at the address of another slot generation is rejected."),
        vector("aws-atomic-publication-replay-contradictory-prior-state", ["AWS-28"], "settlement", replay_contradiction, "fail", "A network-signed replay publication whose prior state is other content is contradictory."),
        *(
            vector(f"aws-evidence-address-{label}", ["AWS-23"], "settlement", address_variant(address), "error", "A syntactically malformed Atomic evidence address is malformed input, not a mismatch.")
            for label, address in malformed_addresses.items()
        ),
        vector("aws-slot-claim-generation-advanced", ["AWS-4"], "slot", slot_claim_advanced, "fail", "A claim CAS keeps the expected generation; an advanced generation is an invalid transition."),
        vector("aws-slot-inflight-replay-other-work", ["AWS-9"], "slot", inflight_other, "fail", "A network-signed in-flight slot for another Work is not an exact replay."),
        vector("aws-slot-settled-replay-other-receipt", ["AWS-10"], "slot", settled_other, "fail", "A settled replay returns the authoritative receipt commitment and no other."),
        vector("aws-slot-replay-executes-transfer", ["AWS-9"], "slot", replay_transfer, "fail", "An exact replay executes no further transfer."),
        vector("aws-slot-job-id-first-character-8", ["AWS-1"], "slot", job_id_8_slot, "fail", "A slot key jobId starting with 8 is not a canonical JID-1 session."),
        vector("aws-settlement-receipt-ref-version-unsupported", ["AWS-19"], "settlement", resettled(final_bound, lambda e: e["workReceiptRef"].update(refVersion="2")), "fail", "A re-signed workReceiptRef with refVersion 2 is not the AtomicWorkReceiptRefV1 the verifier resolves."),
        vector("aws-atomic-publication-anchor-version-unsupported", ["AWS-28"], "settlement", publication_version_two, "fail", "A publication AnchorReceipt with receiptVersion 2 is not the CORE §5.1 finalized AnchorReceipt AWS-28 requires."),
        vector("aws-settlement-capability-other-network", ["AWS-19"], "settlement", settlement_network, "fail", "Settlement evidence is verified only under a capability for its own networkId."),
    ]

    audit_wrong_hash = base("awb-idempotent-nonpaying-audit-tail")
    audit_wrong_hash["dependencyProofs"][0]["receiptContentHash"] = "00" * 32
    audit = [
        vector("awb-audit-dependency-proof-wrong-receipt-hash", ["AWB-2"], "audit", audit_wrong_hash, "fail", "A dependency proof naming other receipt bytes does not bind a finalized Work operation."),
    ]
    return {
        "atomic-work-identity-v0.1": identity,
        "atomic-work-authorization-v0.1": authorization,
        "atomic-work-execution-recovery-v0.1": execution,
        "atomic-work-purchase-completion-v0.1": purchase_completion,
        "atomic-work-settlement-slot-v0.1": settlement,
        "atomic-work-audit-role-v0.1": audit,
    }


BUILDERS = {
    "atomic-work-identity-v0.1": identity_vectors,
    "atomic-work-authorization-v0.1": authorization_vectors,
    "atomic-work-execution-recovery-v0.1": execution_vectors,
    "atomic-work-purchase-completion-v0.1": purchase_completion_vectors,
    "atomic-work-settlement-slot-v0.1": settlement_slot_vectors,
    "atomic-work-audit-role-v0.1": audit_role_vectors,
}


def build_sets() -> dict[str, dict[str, Any]]:
    built_vectors = {
        name: builder()
        for name, builder in BUILDERS.items()
    }
    for name, vectors in predicate_pin_vectors(built_vectors).items():
        built_vectors[name].extend(vectors)
    observed = {"P": set(), "N": set(), "B": set()}
    for vectors in built_vectors.values():
        for item in vectors:
            if item["caseClass"] == "acceptance":
                observed["P"].update(item["ruleRefs"])
            elif item["caseClass"] == "rejection":
                observed["N"].update(item["ruleRefs"])
            observed["B"].update(item.get("boundaryRuleRefs", []))
    not_applicable = {
        "P": set(POLARITY_NOT_APPLICABLE["P"]),
        "N": set(POLARITY_NOT_APPLICABLE["N"]),
        "B": ATOMIC_RULES - BOUNDARY_APPLICABLE_RULES,
    }
    missing = {
        mark: ATOMIC_RULES - observed[mark] - not_applicable[mark]
        for mark in ("P", "N", "B")
    }
    conflicting = {
        mark: observed[mark] & not_applicable[mark]
        for mark in ("P", "N", "B")
    }
    if any(conflicting.values()):
        rendered = "; ".join(
            f"{mark}: {', '.join(sorted(rules))}"
            for mark, rules in conflicting.items()
            if rules
        )
        raise AssertionError(f"observed Atomic polarity marked not applicable: {rendered}")
    if any(missing.values()):
        rendered = "; ".join(
            f"{mark}: {', '.join(sorted(rules))}"
            for mark, rules in missing.items()
            if rules
        )
        raise AssertionError(f"uncovered applicable Atomic polarity: {rendered}")

    result = {}
    for name, vectors in built_vectors.items():
        disclosed_roles = [
            role for role in SEEDS
            if role != "alternate-seller"
            or name == "atomic-work-purchase-completion-v0.1"
        ]
        disclosed_public_keys = {
            CLAIMS[role]: ref.b64u(ref.ed25519_public_key(SEEDS[role]))
            for role in disclosed_roles
        }
        polarity = {"acceptance": set(), "rejection": set(), "boundary": set()}
        for item in vectors:
            if item["caseClass"] == "acceptance":
                polarity["acceptance"].update(item["ruleRefs"])
            elif item["caseClass"] == "rejection":
                polarity["rejection"].update(item["ruleRefs"])
            polarity["boundary"].update(item.get("boundaryRuleRefs", []))
        result[name] = {
            "set": name,
            "spec": SET_SPECS[name],
            "provenance": {
                "generator": "scripts/generate_atomic_work_vectors.py",
                "reference": "scripts/atomic_work_reference.py",
                "canonicalisation": "RFC 8785 JCS via scripts/jcs.py; set hash is SHA-256 over JCS(vectors).",
                "signatures": "Ed25519 over domain || lowercase SHA-256 hex using fixed public test seeds; dependency-free RFC 8032 verifier.",
                "status": "candidate — no Demos runtime guarantee and no second-implementation cross-run yet",
                "syntheticProofProfile": "demos-bft-proof/test-1 fixtures define outputHash as SHA-256(JCS(storageOutput)), SHA-256(JCS(native transfer payload)), or SHA-256(JCS({accepted:true,operationId})); effectsRoot is SHA-256(JCS({pre,post})). These are test-only formulas, not production Demos wire claims.",
            },
            "publicKeys": disclosed_public_keys,
            "seeds": {role: SEEDS[role].hex() for role in disclosed_roles},
            "count": len(vectors),
            "hash": ref.vector_hash(vectors),
            "coverage": {
                "classification": "candidate-complete-applicable-polarity",
                "applicabilityProfile": "atomic-v0.1-explicit",
                "acceptanceRuleCount": len(polarity["acceptance"]),
                "rejectionRuleCount": len(polarity["rejection"]),
                "boundaryRuleCount": len(polarity["boundary"]),
                "note": "Across the generated corpus, every applicable positive/negative/boundary cell of every rule ID has a rule-referenced fixture of the matching verdict class, and every non-applicable cell carries an explicit rationale; the generator and the strict validator both refuse a gap. Boundary cells count only boundaryRuleRefs. This gate counts rule references by class; it does not show that each fixture exercises its rule. Some cells are currently decided by self-reported or caller-supplied values, and strengthening them to the semantically meaningful fixtures CONFORMANCE-PLAN §14.8 requires remains open for this candidate.",
            },
            "vectors": vectors,
        }
    return result


def render(data: dict[str, Any]) -> str:
    return ref.render_set(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    sets = build_sets()
    errors = []
    for name, data in sets.items():
        path = VECTOR_DIR / f"{name}.json"
        wanted = render(data)
        if args.write:
            path.write_text(wanted, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)} ({data['count']} vectors; {data['hash']})")
            continue
        actual = path.read_text(encoding="utf-8") if path.exists() else ""
        if actual != wanted:
            errors.append(name)
            diff = difflib.unified_diff(
                actual.splitlines(), wanted.splitlines(),
                fromfile=str(path.relative_to(ROOT)), tofile="regenerated", lineterm="",
            )
            print("\n".join(list(diff)[:80]), file=sys.stderr)
    if errors:
        print(f"atomic Work vector regeneration FAILED: {', '.join(errors)}", file=sys.stderr)
        return 1
    if args.check:
        print(f"atomic Work vector regeneration OK ({len(sets)} byte-identical sets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
