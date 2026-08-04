#!/usr/bin/env python3
"""Hydrate SEB candidate vectors with deterministic signed execution authorities."""

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

import generate_evidence_bound_fault_bundle_fixture as F


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "conformance" / "vectors" / "security" / "bundle-settlement-evidence-bijection-v0.4.json"


def make_listing(name, pipeline, signing_keys, signer_role="seller"):
    listing = {
        "listingId": f"listing-seb-{name}",
        "listingVersion": 1,
        "sellerPrimaryClaim": F.CLAIMS["seller"],
        "pipeline": [{"kind": kind} for kind in pipeline],
    }
    payload = (F.LISTING_DOMAIN + F.listing_hash(listing)).encode("utf-8")
    listing["signature"] = {
        "signer": F.CLAIMS[signer_role],
        "algorithm": "ed25519",
        "value": F.b64u(signing_keys[signer_role].sign(payload)),
    }
    return listing


def authority_reference(name, phase_key):
    label = f"SEB-AUTHORITY:{name}:{phase_key}"
    return {
        "anchor": {
            "kind": "storage-program",
            "locator": f"stor-{hashlib.sha256(label.encode()).hexdigest()}",
        },
        "contentHash": hashlib.sha256(("content:" + label).encode()).hexdigest(),
    }


def make_authority(name, definition, signing_keys):
    listing = make_listing(
        name,
        definition["listingPipeline"],
        signing_keys,
        definition.get("listingSignerRole", "seller"),
    )
    phase_summary = []
    settlement_evidence = []
    for source in definition["phaseSummary"]:
        entry = copy.deepcopy(source)
        if entry["kind"] in F.EVIDENCE_PHASES:
            ref = authority_reference(name, f"{entry['index']}:{entry['kind']}")
            entry["attestationRef"] = ref
            settlement_evidence.append(ref)
        phase_summary.append(entry)

    bundle = {
        "evidenceBoundFaultBundleVersion": "1",
        "jobId": f"SEB-AUTHORITY-{name}",
        "outcome": definition["bundleOutcome"],
        "faultedParty": "none" if definition["bundleOutcome"] == "completed" else "seller",
        "anchoredByRole": "seller",
        "listingRef": {
            "listingId": listing["listingId"],
            "version": listing["listingVersion"],
            "contentHash": F.listing_hash(listing),
        },
        "parties": [
            {"role": "buyer", "bundleHash": hashlib.sha256(b"seb-buyer-bundle").hexdigest(), "primaryClaim": F.CLAIMS["buyer"]},
            {"role": "seller", "bundleHash": hashlib.sha256(b"seb-seller-bundle").hexdigest(), "primaryClaim": F.CLAIMS["seller"]},
        ],
        "phaseSummary": phase_summary,
        "vetRecords": [],
        "settlementEvidence": settlement_evidence,
        "recipeRegistryVersion": 1,
        "railRegistryVersion": 1,
        "finalisedAt": 1785859200000,
        "signatures": [],
    }
    F.sign_bundle(bundle, "evidence-bound", signing_keys)

    if definition.get("corruptListingSignature"):
        value = listing["signature"]["value"]
        listing["signature"]["value"] = ("A" if value[0] != "A" else "B") + value[1:]
    if definition.get("corruptBundleSignature"):
        value = bundle["signatures"][0]["value"]
        bundle["signatures"][0]["value"] = ("A" if value[0] != "A" else "B") + value[1:]

    default_lifecycle = definition["defaultReferenceLifecycle"]
    bundle_lifecycle = copy.deepcopy(definition.get("bundleLifecycle") or (
        {"state": "finalized", "independentlyResolvable": True}
        if definition["bundleOutcome"] == "completed"
        else {"state": "included", "independentlyResolvable": False}
    ))
    reference_validation_by_canonical_ref = {
        F.canonical(ref).decode("utf-8"): {
            "phaseKey": f"{entry['index']}:{entry['kind']}",
            "lifecycle": copy.deepcopy(default_lifecycle),
        }
        for entry, ref in zip(
            (entry for entry in phase_summary if entry["kind"] in F.EVIDENCE_PHASES),
            settlement_evidence,
        )
    }
    return {
        "listing": listing,
        "bundle": bundle,
        "defaultReferenceLifecycle": copy.deepcopy(default_lifecycle),
        "referenceValidationByCanonicalRef": reference_validation_by_canonical_ref,
        "bundleLifecycle": bundle_lifecycle,
    }


def semantic_definitions(data):
    if "executionAuthorityDefinitions" in data:
        return copy.deepcopy(data["executionAuthorityDefinitions"])
    definitions = copy.deepcopy(data["executionAuthorities"])
    for definition in definitions.values():
        if definition.pop("listingSignatureVerified", True) is False:
            definition["corruptListingSignature"] = True
        definition.pop("bundleDiscriminator", None)
        if definition.pop("bundleSignaturesVerified", True) is False:
            definition["corruptBundleSignature"] = True
    return definitions


def generate(source):
    data = copy.deepcopy(source)
    definitions = semantic_definitions(data)
    if "invalid-bundle-signature" not in definitions:
        definitions["invalid-bundle-signature"] = copy.deepcopy(definitions["standard-completed"])
        definitions["invalid-bundle-signature"]["corruptBundleSignature"] = True
    if "mismatched-listing-signer" not in definitions:
        definitions["mismatched-listing-signer"] = copy.deepcopy(definitions["standard-completed"])
        definitions["mismatched-listing-signer"]["listingSignerRole"] = "buyer"
    if "invalid-completed-bundle-lifecycle" not in definitions:
        definitions["invalid-completed-bundle-lifecycle"] = copy.deepcopy(definitions["standard-completed"])
        definitions["invalid-completed-bundle-lifecycle"]["bundleLifecycle"] = {
            "state": "accepted",
            "independentlyResolvable": False,
        }
    definitions["failed-delivery"]["defaultReferenceLifecycle"]["independentlyResolvable"] = False

    vector_name = "bundle-settlement-bijection-invalid-bundle-authority-reject"
    if not any(vector["name"] == vector_name for vector in data["vectors"]):
        data["vectors"].append({
            "name": vector_name,
            "expected": "fail",
            "input": {
                "executionAuthorityRef": "invalid-bundle-signature",
                "topLevelRefs": ["ref-pay", "ref-deliver"],
                "resolvedReferencePhaseKeys": {
                    "ref-pay": "2:pay-dem",
                    "ref-deliver": "3:deliver-attested-payload",
                },
                "pointerMap": {},
                "supersedesEdges": {},
                "unrelatedAuthorityDisposition": "verified",
            },
            "want": {"disposition": "rejected", "reasonCode": "execution-authority"},
        })
    signer_vector_name = "bundle-settlement-bijection-mismatched-listing-signer-reject"
    if not any(vector["name"] == signer_vector_name for vector in data["vectors"]):
        data["vectors"].append({
            "name": signer_vector_name,
            "expected": "fail",
            "input": {
                "executionAuthorityRef": "mismatched-listing-signer",
                "topLevelRefs": ["ref-pay", "ref-deliver"],
                "resolvedReferencePhaseKeys": {
                    "ref-pay": "2:pay-dem",
                    "ref-deliver": "3:deliver-attested-payload",
                },
                "pointerMap": {},
                "supersedesEdges": {},
                "unrelatedAuthorityDisposition": "verified",
            },
            "want": {"disposition": "rejected", "reasonCode": "execution-authority"},
        })
    lifecycle_vector_name = "bundle-settlement-bijection-completed-bundle-not-finalized-reject"
    if not any(vector["name"] == lifecycle_vector_name for vector in data["vectors"]):
        data["vectors"].append({
            "name": lifecycle_vector_name,
            "expected": "fail",
            "input": {
                "executionAuthorityRef": "invalid-completed-bundle-lifecycle",
                "topLevelRefs": ["ref-pay", "ref-deliver"],
                "resolvedReferencePhaseKeys": {
                    "ref-pay": "2:pay-dem",
                    "ref-deliver": "3:deliver-attested-payload",
                },
                "pointerMap": {},
                "supersedesEdges": {},
                "unrelatedAuthorityDisposition": "verified",
            },
            "want": {"disposition": "rejected", "reasonCode": "execution-authority"},
        })
    failed_positive = next(
        vector for vector in data["vectors"]
        if vector["name"] == "bundle-settlement-bijection-failed-phase-included-pass"
    )
    failed_positive["input"]["referenceLifecycleByRef"] = {
        "ref-failed-delivery": {
            "state": "included",
            "independentlyResolvable": False,
        }
    }

    signing_keys = F.keys()
    data["generator"] = "scripts/generate_bundle_settlement_evidence_vectors.py"
    data["seeds"] = F.SEEDS
    data["publicKeys"] = {
        F.CLAIMS[role]: F.b64u(key.public_key().public_bytes_raw())
        for role, key in signing_keys.items()
    }
    data["domains"] = {
        "listing": F.LISTING_DOMAIN,
        "evidenceBoundBundle": F.DOMAINS["evidence-bound"],
    }
    data["executionAuthorityDefinitions"] = definitions
    data["executionAuthorities"] = {
        name: make_authority(name, definition, signing_keys)
        for name, definition in definitions.items()
    }
    data["count"] = len(data["vectors"])
    data["hash"] = hashlib.sha256(F.canonical(data["vectors"])).hexdigest()
    return data


def encoded(source):
    return (json.dumps(generate(source), indent=2, ensure_ascii=False) + "\n").encode()


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source = json.loads(TARGET.read_text(encoding="utf-8"))
    generated = encoded(source)
    if args.write:
        TARGET.write_bytes(generated)
        print(f"wrote {TARGET.relative_to(ROOT)}")
        return 0
    if TARGET.read_bytes() != generated:
        print(f"{TARGET.relative_to(ROOT)} is stale; run this script with --write", file=sys.stderr)
        return 1
    print(f"verified {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
