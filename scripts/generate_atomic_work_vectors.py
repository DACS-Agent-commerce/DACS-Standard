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
COMPOSED_PROOF_RESERVATION_BYTES = 19_000


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


def identity_bundle(role: str, extra_claims: list[str] | None = None) -> dict[str, Any]:
    claims = [CLAIMS[role], *(extra_claims or [])]
    claim_records = []
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
) -> dict[str, Any]:
    del job_id  # listing bytes are intentionally reusable across sessions.
    deliverable = {
        "kind": "storage-program", "schemaUrl": "https://dacs.dev/result-v1.json",
        "expectedSizeBytes": len(b"deterministic-result-v1"), "accessModel": "public",
    }
    unsigned: dict[str, Any] = {
        "dacsVersion": "1", "listingVersion": 1, "listingId": "atomic-fixed-1",
        "seller": {"identity": identity_bundle("seller"), "displayName": "Atomic Seller"},
        "offering": {
            "title": "Deterministic result", "description": "Atomic vector fixture",
            "category": "test.atomic", "tags": ["atomic"], "deliverable": deliverable,
        },
        "buyerRequirement": {"requirementVersion": "1", "required": [], "party": CLAIMS["buyer"]},
        "pipeline": [
            {"kind": "negotiate-fixed-price"},
            {"kind": (
                "commit-payee-bound-agreement" if payee_bound
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
    payout_address: str = "dem-test-seller",
    payout_bindings: list[dict[str, Any]] | None = None,
    agreement_domain: bytes | None = None,
    vet_records: dict[str, dict[str, Any]] | None = None,
    vet_ref_overrides: dict[str, dict[str, Any]] | None = None,
    omit_vet_refs: set[str] | None = None,
    seller_role: str = "seller",
) -> dict[str, Any]:
    listing = listing_fixture(job_id, payee_bound=payee_bound)
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
            "payeeBoundAgreementVersion" if payee_bound else "agreementVersion"
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
    if payee_bound:
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
            ref._PAYEE_BOUND_AGREEMENT_DOMAIN
            if payee_bound else ref._AGREEMENT_DOMAIN
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
        "observedAt": 1_799_999_751_000,
        "blockRef": {
            "id": f"block-{label}-750", "height": "750",
            "timestamp": 1_799_999_750_000,
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


def authorization_authority(intent: dict[str, Any]) -> dict[str, Any]:
    agreement = intent["operations"][2]["payload"]["artifact"]
    payee_bound = "payeeBoundAgreementVersion" in agreement
    record = intent["operations"][3]["payload"]["artifact"]
    rail = rail_definition(intent["railId"])
    rail_index, rail_index_receipt, rail_receipt = rail_registry_material(rail)
    session_source = portable_session_context_source(intent)
    atomic_context = atomic_payment_session_context(intent)
    seller_party = next(
        party for party in agreement["parties"] if party["role"] == "seller"
    )
    seller_role = role_for_claim(seller_party["primaryClaim"])
    return {
        "agreement": copy.deepcopy(agreement),
        "listing": listing_fixture(intent["jobId"], payee_bound=payee_bound),
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
    payee_bound: bool = False, payout_address: str = "dem-test-seller",
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
        job_id, payee_bound=payee_bound, payout_address=payout_address,
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
            "maxProofBytes": 20_000,
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
    non_nfc_authorizations = copy.deepcopy(auths)
    non_nfc_authorizations[0]["unknown"] = "e\u0301"
    non_nfc_authorizations[0] = sign_authorization_unchecked(
        non_nfc_authorizations[0], non_nfc_authorizations[0]["role"]
    )
    return [
        vector("aw-auth-complete-envelope", ["AW-30", "AW-31", "AW-32", "AW-33", "AW-34", "AW-35", "AW-36", "AW-38"], "authorization", base, "pass", "Each required role, including the independently authorized payer rather than a Vet signer, signs the unmodified full envelope for this exact Work and context."),
        vector("aw-auth-mutation-invalidates", ["AW-30", "AW-35"], "authorization", {**base, "authorizations": tampered}, "fail", "Mutating a signed envelope member invalidates both binding and signature."),
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
        vector("aw-attempt-byte-identity", ["AW-39", "AW-40"], "attempts", {"intent": intent, "attempts": [attempt_a], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "authority": authorization_authority(intent), "publicKeys": PUBLIC_KEYS}, "pass", "Native attempt identity is distinct while Work bytes, authorizations, and workId remain immutable."),
        vector("aw-attempt-changed-bytes", ["AW-39"], "attempts", {"intent": intent, "attempts": [{**attempt_a, "canonicalWorkBytes": canonical + " "}], "winningAttemptId": "attempt-a", "businessEffectAttempts": [], "authority": authorization_authority(intent), "publicKeys": PUBLIC_KEYS}, "fail", "Replacement cannot alter canonical Work bytes."),
        vector("aw-replacement-with-noninclusion", ["AW-41"], "attempts", {"intent": intent, "attempts": [attempt_a_non, attempt_b_replacement], "winningAttemptId": None, "businessEffectAttempts": [], "publicKeys": PUBLIC_KEYS}, "pass", "Authenticated authoritative non-inclusion permits a replacement attempt under the replacement-authority rule."),
        vector("aw-replacement-on-not-found", ["AW-41", "AW-42"], "attempts", {"intent": intent, "attempts": [unresolved_attempt, attempt_b_replacement], "winningAttemptId": None, "businessEffectAttempts": [], "publicKeys": PUBLIC_KEYS}, "indeterminate", "Ordinary not-found remains on the indeterminate side of the replacement-authority boundary.", boundary_rules=["AW-42"]),
        vector("aw-single-ledger-winner", ["AW-43", "AW-44"], "attempts", {"intent": intent, "attempts": [attempt_a, attempt_b], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "publicKeys": PUBLIC_KEYS}, "pass", "Exactly one included winner and business effect is the maximum valid cardinality.", boundary_rules=["AW-43", "AW-44"]),
        vector("aw-two-included-attempts", ["AW-43", "AW-44"], "attempts", {"intent": intent, "attempts": [attempt_a, {**attempt_b, "lifecycleEvidence": ledger_evidence("attempt-b", wid, "included-committed", tx_b)}], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a", "attempt-b"], "publicKeys": PUBLIC_KEYS}, "fail", "A second included winner/effect crosses the Work-ledger cardinality boundary.", boundary_rules=["AW-43", "AW-44"]),
        vector("aw-attempt-evidence-native-ref-mismatch", ["AW-40", "AW-59"], "attempts", {"intent": intent, "attempts": [{**attempt_a, "lifecycleEvidence": wrong_native_evidence}], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "publicKeys": PUBLIC_KEYS}, "fail", "Signed lifecycle evidence for another native transaction cannot be attached to this attempt."),
        vector("aw-exact-replay-returns-winner", ["AW-45"], "attempts", {"intent": intent, "attempts": [attempt_a, exact_replay], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "publicKeys": PUBLIC_KEYS}, "pass", "Exact replay returns the selected winner without execution or another fee/nonce effect."),
        vector("aw-attempt-class-required", ["AW-39", "AW-41", "AW-45"], "attempts", {"intent": intent, "attempts": [missing_attempt_class], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "publicKeys": PUBLIC_KEYS}, "fail", "Every transport attempt declares exactly one normal, replacement, or replay class before class-specific fields are interpreted."),
        vector("aw-attempt-native-reference-duplicate", ["AW-39", "AW-40", "AW-43"], "attempts", {"intent": intent, "attempts": [attempt_a, duplicate_native_ref_attempt], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "publicKeys": PUBLIC_KEYS}, "fail", "A second attempt ID naming the first canonical native reference crosses the one-to-one identity boundary.", boundary_rules=["AW-40"]),
        vector("aw-receipt-ledger-winner-bound", ["AW-43", "AW-46"], "attempts", {"intent": intent, "attempts": [receipt_attempt], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "receipt": committed, "publicKeys": PUBLIC_KEYS}, "pass", "Receipt winner ID and native reference equal the authenticated ledger-selected attempt."),
        vector("aw-receipt-ledger-winner-mismatch", ["AW-43", "AW-46"], "attempts", {"intent": intent, "attempts": [receipt_attempt], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "receipt": wrong_winner_receipt, "publicKeys": PUBLIC_KEYS}, "fail", "A separately finalized receipt cannot name another winning attempt."),
        vector("aw-exact-replay-additional-fee", ["AW-45", "AW-56", "AW-57"], "attempts", {"intent": intent, "attempts": [attempt_a, charged_replay], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "publicKeys": PUBLIC_KEYS}, "fail", "An exact replay returns the old winner with zero additional fee and nonce effects."),
        vector("aw-exact-replay-candidate-nonce", ["AW-45", "AW-56", "AW-57"], "attempts", {"intent": intent, "attempts": [attempt_a, replay_with_nonce], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "publicKeys": PUBLIC_KEYS}, "fail", "The generic replay arm permits profile-selected nonce policy, but this advertised candidate fee rule forbids a new replay nonce."),
        vector("aw-nonwinning-attempt-fee-rule", ["AW-39", "AW-56", "AW-57"], "attempts", {"intent": intent, "attempts": [attempt_a, nonwinning_wrong_fee], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "publicKeys": PUBLIC_KEYS}, "fail", "The selected fee rule applies to every normal or replacement submission, not only the included winner."),
        vector("aw-attempt-authenticated-nonce-mismatch", ["AW-39", "AW-40", "AW-46", "AW-56"], "attempts", {"intent": intent, "attempts": [substituted_attempt_nonce], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "publicKeys": PUBLIC_KEYS}, "fail", "The winning attempt nonce and fee must equal the subject authenticated by its ledger lifecycle evidence."),
        vector("aw-replacement-replay-class-confusion", ["AW-41", "AW-45", "AW-56"], "attempts", {"intent": intent, "attempts": [attempt_a_non, mixed_replacement_replay], "winningAttemptId": None, "businessEffectAttempts": [], "publicKeys": PUBLIC_KEYS}, "fail", "An attempt cannot be classified simultaneously as a replacement and an exact replay, and replay requires an authenticated winner."),
        vector("aw-receipt-ledger-outcome-mismatch", ["AW-43", "AW-46"], "attempts", {"intent": intent, "attempts": [rolled_back_winner_for_committed_receipt], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "receipt": committed, "publicKeys": PUBLIC_KEYS}, "fail", "A committed receipt cannot be paired with an authenticated included-rolled-back winner state."),
        vector("aw-attempt-proof-profile-mismatch", ["AW-40", "AW-48"], "attempts", {"intent": intent, "attempts": [wrong_attempt_proof_profile], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "publicKeys": PUBLIC_KEYS}, "fail", "Attempt lifecycle evidence binds the capability-selected proof profile and validator set."),
        vector("aw-attempt-candidate-lifecycle-shape", ["AW-40"], "attempts", {"intent": intent, "attempts": [extended_candidate_lifecycle], "winningAttemptId": "attempt-a", "businessEffectAttempts": ["attempt-a"], "publicKeys": PUBLIC_KEYS}, "fail", "The generic schema leaves lifecycle evidence to the selected profile; this candidate accepts only its complete closed synthetic witness shape."),
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
    purchase = purchase_intent()
    purchase_receipt = final_receipt(purchase)
    completion = completion_intent(purchase_receipt)
    purchase_base = {
        "intent": purchase, "publicKeys": PUBLIC_KEYS,
        "listing": listing_fixture(purchase["jobId"]),
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
    completion_base = {"intent": completion, "purchaseIntent": purchase, "purchaseCommitmentProjection": purchase_commitment_projection, "listing": listing_fixture(purchase["jobId"]), "authenticatedOrchestrator": CLAIMS["orchestrator"], "publicKeys": PUBLIC_KEYS, "claimsEvidenceFinalized": False, "claimsBundleFinalized": False}
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
    sequential_purchase = purchase_intent(gate_mode="sequential")
    sequential_purchase_receipt = final_receipt(sequential_purchase)
    composed_sequential_purchase = composed_purchase_admission(
        sequential_purchase, sequential_purchase_receipt
    )
    mismatched_gate_copy = copy.deepcopy(composed_purchase)
    mismatched_gate_copy["authority"]["gateMode"] = "sequential"
    alternate_seller_purchase = purchase_intent(
        seller_role="alternate-seller"
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
    mismatched_completion = completion_intent(
        purchase_receipt, gate_mode="sequential"
    )
    mismatched_completion_admission = composed_completion_admission(
        purchase, purchase_receipt, mismatched_completion,
        final_receipt(mismatched_completion),
    )
    failed_purchase = purchase_intent()
    failed_purchase_receipt = final_receipt(
        failed_purchase, "rolled-back", 4
    )
    retry_purchase = purchase_intent(
        generation=failed_purchase_receipt["paymentSlot"]["after"]["generation"],
        expected_state="rolled-back",
        prior_failure=failed_purchase_receipt["receiptCommitment"],
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
        vector("awp-purchase-signed-sequential-admission", ["AWP-6", "AWP-7", "AWP-12"], "purchase-admission", composed_sequential_purchase, "pass", "A signed sequential gate selection is admitted only with the independently verified finalized commitment AnchorReceipt required before payment.", boundary_rules=["AWP-12"]),
        vector("awp-purchase-caller-gate-mode-mismatch", ["AWP-6"], "purchase-admission", mismatched_gate_copy, "fail", "An unsigned caller authority copy cannot change the proof path selected by the signed Work intent."),
        vector("awp-purchase-agreement-seller-differs-from-listing", ["AWP-7"], "purchase-admission", alternate_seller_admission, "fail", "A fully re-signed Work and Agreement from another seller cannot substitute for the seller identity that published the pinned Listing."),
        vector("awp-purchase-composed-retry-admission", ["AWP-5", "AWP-10", "AWP-11", "AWS-10", "AWS-11"], "purchase-admission", composed_retry, "pass", "A complete retry proves the prior rolled-back Work receipt, advances generation N to N+1, and carries that same generation through the terminal receipt and settlement."),
        vector("awp-purchase-composed-retry-generation-skip", ["AWP-10", "AWP-11", "AWS-10", "AWS-11"], "purchase-admission", composed_retry_generation_skip, "fail", "A retry cannot skip a generation or present a slot transition that differs from its terminal receipt."),
        vector("awp-completion-composed-admission", ["AWP-13", "AWP-14", "AWP-15", "AWP-16"], "completion-admission", composed_completion, "pass", "One Completion verifier consumes the finalized Purchase and exact authority context through delivery settlement."),
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
        "businessEffectAttempts": [receipt["winningAttempt"]["attemptId"]],
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
        "businessEffectAttempts": [receipt["winningAttempt"]["attemptId"]],
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
        vector("awb-audit-dependency-proof-missing", ["AWB-8", "AWB-10"], "audit", missing_dependency_proof, "indeterminate", "A missing Purchase or Completion operation proof leaves audit finalisation indeterminate.", boundary_rules=["AWB-10"]),
        vector("awb-audit-replay-no-duplicate", ["AWB-9"], "audit", replay_audit, "pass", "An authenticated exact lifecycle replay produces no duplicate effect."),
        vector("awb-audit-replay-competing-bytes", ["AWB-8", "AWB-9"], "audit", overwrite_audit, "fail", "A cryptographically valid competing-byte write cannot overwrite the immutable audit address.", boundary_rules=["AWB-8"]),
        vector("awb-repair-never-replays-purchase", ["AWB-10"], "audit", repair_payment, "fail", "Repair/finalization never contains payment or slot operations."),
    ]


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
                "note": "Across the generated corpus, every applicable rule polarity has a fixture; non-applicable cells require an explicit rationale, and boundaryRuleRefs attribute only the rule edges actually exercised.",
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
