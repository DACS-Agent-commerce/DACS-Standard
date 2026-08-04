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
    reference_validation_by_canonical_ref = {}
    job_id = f"SEB-AUTHORITY-{name}"
    default_lifecycle = definition["defaultReferenceLifecycle"]
    for source in definition["phaseSummary"]:
        entry = copy.deepcopy(source)
        if entry["kind"] in F.EVIDENCE_PHASES:
            supersedes = None
            if definition.get("st8Resolved") and entry["kind"] in {
                "pay-cross-chain-htlc",
                "pay-cross-chain-liquidity-tank",
            }:
                interim_record, interim_ref = F.make_evidence(
                    job_id,
                    entry["kind"],
                    entry["index"],
                    signing_keys,
                    outcome="failure",
                    reason=(
                        "dest-revealed-source-unclaimed"
                        if entry["kind"] == "pay-cross-chain-htlc"
                        else "tank-locked-unreleased"
                    ),
                    label_suffix=":interim",
                )
                reference_validation_by_canonical_ref[F.canonical(interim_ref).decode("utf-8")] = {
                    "phaseIndex": entry["index"],
                    "record": interim_record,
                    "lifecycle": copy.deepcopy(default_lifecycle),
                }
                supersedes = interim_ref
            record, ref = F.make_evidence(
                job_id,
                entry["kind"],
                entry["index"],
                signing_keys,
                outcome="success" if entry["outcome"] == "ok" else "failure",
                reason=entry.get("errorClass"),
                supersedes=supersedes,
                label_suffix=":resolved" if supersedes is not None else "",
            )
            entry["attestationRef"] = ref
            settlement_evidence.append(ref)
            reference_validation_by_canonical_ref[F.canonical(ref).decode("utf-8")] = {
                "phaseIndex": entry["index"],
                "record": record,
                "lifecycle": copy.deepcopy(default_lifecycle),
            }
        phase_summary.append(entry)

    bundle = {
        "evidenceBoundFaultBundleVersion": "1",
        "jobId": job_id,
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

    bundle_lifecycle = copy.deepcopy(definition.get("bundleLifecycle") or (
        {"state": "finalized", "independentlyResolvable": True}
        if definition["bundleOutcome"] == "completed"
        else {"state": "included", "independentlyResolvable": False}
    ))
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
    data["inputModel"] = (
        "executionAuthorityRef selects a domain-verified EBFAB phaseSummary plus its "
        "content-hash-bound, signature-verified DACS-1 listing pipeline; the evaluator "
        "requires an ordered, outcome-consistent execution prefix and derives phase keys "
        "locally. authenticatedRecordByRef represents independently resolved, job-bound "
        "SettlementEvidence content; record outcome and hashed supersedesEvidenceRef, not "
        "caller-supplied class or edge labels, determine ST-8 terminal selection. Completed "
        "authorities require finalized and independently resolvable evidence; failed or "
        "aborted authorities require included or finalized evidence. Optional pointers never "
        "create phase authority."
    )
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
    definitions["single-htlc-completed"]["st8Resolved"] = True
    definitions["single-htlc-expired"] = copy.deepcopy(definitions["single-htlc-completed"])
    definitions["single-htlc-expired"].pop("st8Resolved", None)
    definitions["single-htlc-expired"]["bundleOutcome"] = "failed-counterparty"
    definitions["single-htlc-expired"]["phaseSummary"][-1].update({
        "outcome": "fail",
        "errorClass": "settlement-atomicity",
    })
    definitions["single-htlc-expired"]["defaultReferenceLifecycle"] = {
        "state": "included",
        "independentlyResolvable": False,
    }
    definitions["invalid-completed-incomplete-summary"] = copy.deepcopy(
        definitions["standard-completed"]
    )
    definitions["invalid-completed-incomplete-summary"]["phaseSummary"] = []
    definitions["invalid-failed-gapped-summary"] = copy.deepcopy(definitions["standard-completed"])
    definitions["invalid-failed-gapped-summary"]["bundleOutcome"] = "failed-perm"
    definitions["invalid-failed-gapped-summary"]["phaseSummary"] = [
        copy.deepcopy(definitions["standard-completed"]["phaseSummary"][0]),
        {
            **copy.deepcopy(definitions["standard-completed"]["phaseSummary"][2]),
            "outcome": "fail",
            "errorClass": "permanent",
        },
    ]
    definitions["invalid-aborted-result-summary"] = copy.deepcopy(definitions["aborted-before-result"])
    definitions["invalid-aborted-result-summary"]["phaseSummary"] = [{
        "index": 0,
        "kind": definitions["aborted-before-result"]["listingPipeline"][0],
        "outcome": "fail",
        "errorClass": "counterparty",
    }]

    for vector in data["vectors"]:
        if vector["name"] == "bundle-settlement-bijection-st8-expired-interim-pass":
            vector["input"]["executionAuthorityRef"] = "single-htlc-expired"

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
    incomplete_trace_name = "bundle-settlement-bijection-incomplete-completed-summary-reject"
    if not any(vector["name"] == incomplete_trace_name for vector in data["vectors"]):
        data["vectors"].append({
            "name": incomplete_trace_name,
            "expected": "fail",
            "input": {
                "executionAuthorityRef": "invalid-completed-incomplete-summary",
                "topLevelRefs": [],
                "resolvedReferencePhaseKeys": {},
                "pointerMap": {},
                "recordClassByRef": {},
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
    for vector in data["vectors"]:
        vector_input = vector["input"]
        if "resolvedReferencePhaseKeys" not in vector_input:
            continue
        resolved = vector_input.pop("resolvedReferencePhaseKeys")
        record_classes = vector_input.pop("recordClassByRef", {})
        supersedes = vector_input.pop("supersedesEdges", {})
        authority = data["executionAuthorities"].get(vector_input.get("executionAuthorityRef"))
        job_id = authority["bundle"]["jobId"] if authority else "unresolved-authority"
        outcome_by_key = {
            f"{entry['index']}:{entry['kind']}": (
                "success" if entry["outcome"] == "ok" else "failure"
            )
            for entry in (authority or {}).get("bundle", {}).get("phaseSummary", [])
        }
        authenticated_records = {}
        for ref, phase_key in resolved.items():
            record_class = record_classes.get(ref)
            outcome = outcome_by_key.get(phase_key, "success")
            if record_class == "st8-resolved-success":
                outcome = "success"
            elif record_class == "st8-expired-interim-failure":
                outcome = "failure"
            record = {
                "jobId": job_id,
                "phaseKey": phase_key,
                "outcome": outcome,
            }
            if ref in supersedes:
                record["supersedesEvidenceRef"] = supersedes[ref]
            authenticated_records[ref] = record
        vector_input["authenticatedRecordByRef"] = authenticated_records
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
