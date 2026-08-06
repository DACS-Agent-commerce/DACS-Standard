#!/usr/bin/env python3
"""Generate the signed DACS-5 v0.4 EBFAB compatibility fixture.

The fixture uses published synthetic Ed25519 test seeds. It proves the new bundle
domain over real signatures, discriminator exclusivity/refusal, cross-type replay
failure, and the EBFAB > FAB > legacy authority rule for non-divergent pairs.
"""

import argparse
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "conformance" / "fixtures" / "evidence-bound-fault-bundle-compatibility-v0.4.json"
SEEDS = {
    "buyer": "a1" * 32,
    "seller": "c3" * 32,
    "orchestrator": "0e" * 32,
}
CLAIMS = {role: f"did:demos:{role}" for role in SEEDS}
DOMAINS = {
    "legacy": "dacs-bundle:v1:",
    "fault": "dacs-fault-bundle:v1:",
    "evidence-bound": "dacs-evidence-bound-fault-bundle:v1:",
}
LISTING_DOMAIN = "dacs-listing:v1:"
SETTLEMENT_EVIDENCE_DOMAIN = "dacs-evidence:v1:"
POINTER_DOMAINS = {
    "fault": "dacs-fault-bundle-pointer:v1:",
    "evidence-bound": "dacs-evidence-bound-fault-bundle-pointer:v1:",
}
DISCRIMINATORS = {
    "legacy": "bundleVersion",
    "fault": "faultBundleVersion",
    "evidence-bound": "evidenceBoundFaultBundleVersion",
}
EVIDENCE_PHASES = {
    "pay-evm-erc20",
    "pay-solana-spl",
    "pay-cross-chain-htlc",
    "pay-cross-chain-liquidity-tank",
    "pay-ap2",
    "pay-x402",
    "pay-dem",
    "deliver-storage-program",
    "deliver-entitlement",
    "deliver-attested-payload",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64u(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def bundle_hash(bundle):
    unsigned = {key: value for key, value in bundle.items() if key not in {"signatures", "anchoredByRole"}}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def listing_hash(listing):
    unsigned = {key: value for key, value in listing.items() if key != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def evidence_hash(record):
    unsigned = {key: value for key, value in record.items() if key != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def pointer_hash(pointer):
    unsigned = {key: value for key, value in pointer.items() if key != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def keys():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return {
        role: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
        for role, seed in SEEDS.items()
    }


def reference(label):
    return {
        "anchor": {"kind": "storage-program", "locator": f"stor-{hashlib.sha256(label.encode()).hexdigest()}"},
        "contentHash": hashlib.sha256(("content:" + label).encode()).hexdigest(),
    }


def make_evidence(job_id, phase, phase_index, signing_keys, *, outcome="success", reason=None,
                  supersedes=None, label_suffix=""):
    record = {
        "evidenceVersion": "1",
        "jobId": job_id,
        "phase": phase,
        "outcome": outcome,
        "observedAt": 1785772799000 + phase_index,
    }
    if outcome == "failure":
        record["reason"] = reason or "permanent"
    elif phase.startswith("pay-"):
        record["paymentAmount"] = {"amount": "1", "currency": "DEM"}
        record["settlementFinality"] = {
            "model": "bft-final",
            "finalityObservedAt": record["observedAt"],
        }
    else:
        record["deliverableContentHash"] = hashlib.sha256(
            f"deliverable:{job_id}:{phase_index}".encode()
        ).hexdigest()
    if supersedes is not None:
        record["supersedesEvidenceRef"] = copy.deepcopy(supersedes)
    payload = (SETTLEMENT_EVIDENCE_DOMAIN + evidence_hash(record)).encode("utf-8")
    record["signature"] = {
        "signer": CLAIMS["seller"],
        "algorithm": "ed25519",
        "value": b64u(signing_keys["seller"].sign(payload)),
    }
    label = f"{job_id}:{phase_index}:{phase}{label_suffix}"
    ref = {
        "anchor": {
            "kind": "storage-program",
            "locator": f"stor-{hashlib.sha256(label.encode()).hexdigest()}",
        },
        "contentHash": evidence_hash(record),
    }
    return record, ref


def make_listing(signing_keys):
    listing = {
        "listingId": "listing-ebfab-compat",
        "listingVersion": 1,
        "sellerPrimaryClaim": CLAIMS["seller"],
        "pipeline": [{"kind": "pay-dem"}],
    }
    payload = (LISTING_DOMAIN + listing_hash(listing)).encode("utf-8")
    listing["signature"] = {
        "signer": CLAIMS["seller"],
        "algorithm": "ed25519",
        "value": b64u(signing_keys["seller"].sign(payload)),
    }
    return listing


def sign_bundle(bundle, kind, signing_keys):
    bundle["signatures"] = []
    payload = (DOMAINS[kind] + bundle_hash(bundle)).encode("utf-8")
    bundle["signatures"] = [
        {
            "party": CLAIMS[role],
            "algorithm": "ed25519",
            "value": b64u(signing_keys[role].sign(payload)),
        }
        for role in ("buyer", "seller")
    ]
    return bundle


def make_bundle(kind, anchored_by_role, signing_keys, listing):
    evidence_record, evidence_ref = make_evidence(
        "EBFAB-COMPAT-1", "pay-dem", 0, signing_keys
    )
    bundle = {
        DISCRIMINATORS[kind]: "1",
        "jobId": "EBFAB-COMPAT-1",
        "outcome": "completed",
        "anchoredByRole": anchored_by_role,
        "listingRef": {
            "listingId": listing["listingId"],
            "version": listing["listingVersion"],
            "contentHash": listing_hash(listing),
        },
        "parties": [
            {"role": "buyer", "bundleHash": hashlib.sha256(b"buyer-bundle").hexdigest(), "primaryClaim": CLAIMS["buyer"]},
            {"role": "seller", "bundleHash": hashlib.sha256(b"seller-bundle").hexdigest(), "primaryClaim": CLAIMS["seller"]},
        ],
        "phaseSummary": [
            {"index": 0, "kind": "pay-dem", "outcome": "ok", "attestationRef": evidence_ref}
        ],
        "vetRecords": [],
        "settlementEvidence": [evidence_ref],
        "recipeRegistryVersion": 1,
        "railRegistryVersion": 1,
        "finalisedAt": 1785772800000,
        "signatures": [],
    }
    if kind != "legacy":
        bundle["faultedParty"] = "none"
    return sign_bundle(bundle, kind, signing_keys), evidence_record


def make_pointer(kind, bundle, signing_keys):
    pointer = {
        DISCRIMINATORS[kind]: "1",
        "pointerKind": "extended",
        "fullBundleUrl": f"https://example.invalid/{kind}-bundle.json",
        "fullBundleContentHash": bundle_hash(bundle),
    }
    return sign_pointer(pointer, kind, signing_keys, bundle.get("anchoredByRole", "seller"))


def sign_pointer(pointer, kind, signing_keys, signer_role):
    pointer.pop("signature", None)
    payload = (POINTER_DOMAINS[kind] + pointer_hash(pointer)).encode("utf-8")
    pointer["signature"] = {
        "signer": CLAIMS[signer_role],
        "algorithm": "ed25519",
        "value": b64u(signing_keys[signer_role].sign(payload)),
    }
    return pointer


def generate():
    signing_keys = keys()
    public_keys = {
        CLAIMS[role]: b64u(key.public_key().public_bytes_raw())
        for role, key in signing_keys.items()
    }
    listing = make_listing(signing_keys)
    ebfab_buyer, evidence_record = make_bundle("evidence-bound", "buyer", signing_keys, listing)
    ebfab_seller, _ = make_bundle("evidence-bound", "seller", signing_keys, listing)
    fab_seller, _ = make_bundle("fault", "seller", signing_keys, listing)
    legacy_seller, _ = make_bundle("legacy", "seller", signing_keys, listing)

    signed_missing_member = copy.deepcopy(ebfab_buyer)
    signed_missing_member["settlementEvidence"] = []
    sign_bundle(signed_missing_member, "evidence-bound", signing_keys)
    signed_pointerless = copy.deepcopy(ebfab_buyer)
    signed_pointerless["phaseSummary"][0].pop("attestationRef")
    sign_bundle(signed_pointerless, "evidence-bound", signing_keys)
    alternate_record, alternate_ref = make_evidence(
        "EBFAB-COMPAT-1", "pay-dem", 0, signing_keys, label_suffix=":alternate"
    )
    ebfab_alternate = copy.deepcopy(ebfab_seller)
    ebfab_alternate["phaseSummary"][0]["attestationRef"] = alternate_ref
    ebfab_alternate["settlementEvidence"] = [alternate_ref]
    sign_bundle(ebfab_alternate, "evidence-bound", signing_keys)

    ebfab_pointer = make_pointer("evidence-bound", ebfab_buyer, signing_keys)
    fab_pointer = make_pointer("fault", fab_seller, signing_keys)
    dual_pointer = copy.deepcopy(fab_pointer)
    dual_pointer["bundleVersion"] = "1"
    invalid_extra_pointer = copy.deepcopy(fab_pointer)
    invalid_extra_pointer["evidenceBoundFaultBundleVersion"] = "2"
    missing_url_pointer = copy.deepcopy(ebfab_pointer)
    missing_url_pointer.pop("fullBundleUrl")
    sign_pointer(missing_url_pointer, "evidence-bound", signing_keys, "buyer")
    malformed_segments_pointer = copy.deepcopy(ebfab_pointer)
    malformed_segments_pointer["segmentRefs"] = ["not-an-attestation-ref"]
    sign_pointer(malformed_segments_pointer, "evidence-bound", signing_keys, "buyer")
    unsafe_url_pointer = copy.deepcopy(ebfab_pointer)
    unsafe_url_pointer["fullBundleUrl"] = "file:///etc/passwd"
    sign_pointer(unsafe_url_pointer, "evidence-bound", signing_keys, "buyer")
    unauthorized_pointer = copy.deepcopy(ebfab_pointer)
    sign_pointer(unauthorized_pointer, "evidence-bound", signing_keys, "seller")
    minimal_ebfab = {"evidenceBoundFaultBundleVersion": "1"}
    minimal_ebfab_pointer = make_pointer("evidence-bound", minimal_ebfab, signing_keys)
    incomplete_binding = {"bundleContentHash": bundle_hash(ebfab_buyer)}

    stripped_to_fab = dict(ebfab_buyer)
    stripped_to_fab.pop("evidenceBoundFaultBundleVersion")
    stripped_to_fab["faultBundleVersion"] = "1"
    dual_discriminator = dict(ebfab_buyer)
    dual_discriminator["faultBundleVersion"] = "1"
    unknown_discriminator = dict(ebfab_buyer)
    unknown_discriminator.pop("evidenceBoundFaultBundleVersion")
    unknown_discriminator["futureBundleVersion"] = "1"
    known_plus_unknown = copy.deepcopy(ebfab_buyer)
    known_plus_unknown["futureBundleVersion"] = "1"
    sign_bundle(known_plus_unknown, "evidence-bound", signing_keys)

    completed_lifecycle = {"state": "finalized", "independentlyResolvable": True}

    return {
        "fixture": "evidence-bound-fault-bundle-compatibility-v0.4",
        "tier": "candidate",
        "generator": "scripts/generate_evidence_bound_fault_bundle_fixture.py",
        "seeds": SEEDS,
        "publicKeys": public_keys,
        "domains": DOMAINS,
        "pointerDomains": POINTER_DOMAINS,
        "listingDomain": LISTING_DOMAIN,
        "listing": listing,
        "referenceValidationByCanonicalRef": {
            canonical(ebfab_buyer["settlementEvidence"][0]).decode("utf-8"): {
                "phaseIndex": 0,
                "authorizedSigner": CLAIMS["seller"],
                "record": evidence_record,
                "lifecycle": {
                    "state": "finalized",
                    "independentlyResolvable": True,
                },
            },
            canonical(alternate_ref).decode("utf-8"): {
                "phaseIndex": 0,
                "authorizedSigner": CLAIMS["seller"],
                "record": alternate_record,
                "lifecycle": {
                    "state": "finalized",
                    "independentlyResolvable": True,
                },
            }
        },
        "validBundleHash": bundle_hash(ebfab_buyer),
        "bundleLifecycleByHash": {
            bundle_hash(bundle): completed_lifecycle
            for bundle in (
                ebfab_buyer,
                ebfab_seller,
                ebfab_alternate,
                signed_pointerless,
                signed_missing_member,
                known_plus_unknown,
            )
        },
        "cases": [
            {"name": "valid-ebfab", "bundle": ebfab_buyer, "want": {"type": "evidence-bound", "signaturesValid": True, "sebValid": True}},
            {"name": "valid-pointerless-ebfab", "bundle": signed_pointerless, "want": {"type": "evidence-bound", "signaturesValid": True, "sebValid": True}},
            {"name": "signed-seb-missing-member-reject", "bundle": signed_missing_member, "want": {"type": "evidence-bound", "signaturesValid": True, "sebValid": False}},
            {"name": "stripped-to-fab-cross-type-replay", "bundle": stripped_to_fab, "want": {"type": "fault", "signaturesValid": False, "sebValid": False}},
            {"name": "dual-discriminator-reject", "bundle": dual_discriminator, "want": {"type": None, "signaturesValid": False, "sebValid": False}},
            {"name": "unknown-discriminator-reject", "bundle": unknown_discriminator, "want": {"type": None, "signaturesValid": False, "sebValid": False}},
            {"name": "known-plus-unknown-discriminator-reject", "bundle": known_plus_unknown, "want": {"type": None, "signaturesValid": False, "sebValid": False}},
            {"name": "completed-bundle-accepted-lifecycle-reject", "bundle": ebfab_buyer, "bundleLifecycle": {"state": "accepted", "independentlyResolvable": False}, "want": {"type": "evidence-bound", "signaturesValid": True, "sebValid": False}},
        ],
        "pairCases": [
            {
                "name": "ebfab-ebfab",
                "copies": {"buyer": ebfab_buyer, "seller": ebfab_seller},
                "want": {"divergent": False, "authoritativeType": "evidence-bound", "authoritativeBundleHash": bundle_hash(ebfab_buyer), "sebValid": True},
            },
            {
                "name": "ebfab-ebfab-member-skew-diverges",
                "copies": {"buyer": ebfab_buyer, "seller": ebfab_alternate},
                "want": {"divergent": True},
            },
            {
                "name": "ebfab-fab-older-cannot-erase-seb",
                "copies": {"buyer": ebfab_buyer, "seller": fab_seller},
                "want": {"divergent": False, "authoritativeType": "evidence-bound", "authoritativeBundleHash": bundle_hash(ebfab_buyer), "sebValid": True},
            },
            {
                "name": "ebfab-legacy-older-cannot-erase-seb",
                "copies": {"buyer": ebfab_buyer, "seller": legacy_seller},
                "want": {"divergent": False, "authoritativeType": "evidence-bound", "authoritativeBundleHash": bundle_hash(ebfab_buyer), "sebValid": True},
            },
        ],
        "pointerCases": [
            {
                "name": "ebfab-pointer-ebfab-pass",
                "pointer": ebfab_pointer,
                "bundle": ebfab_buyer,
                "want": {"ok": True},
            },
            {
                "name": "fab-pointer-ebfab-reject",
                "pointer": fab_pointer,
                "bundle": ebfab_buyer,
                "want": {"ok": False},
            },
            {
                "name": "ebfab-pointer-fab-reject",
                "pointer": ebfab_pointer,
                "bundle": fab_seller,
                "want": {"ok": False},
            },
            {
                "name": "dual-pointer-discriminator-reject",
                "pointer": dual_pointer,
                "bundle": fab_seller,
                "want": {"ok": False},
            },
            {
                "name": "unsupported-extra-pointer-discriminator-reject",
                "pointer": invalid_extra_pointer,
                "bundle": fab_seller,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-missing-url-reject",
                "pointer": missing_url_pointer,
                "bundle": ebfab_buyer,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-malformed-segment-ref-reject",
                "pointer": malformed_segments_pointer,
                "bundle": ebfab_buyer,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-unsafe-url-reject",
                "pointer": unsafe_url_pointer,
                "bundle": ebfab_buyer,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-unauthorized-role-reject",
                "pointer": unauthorized_pointer,
                "bundle": ebfab_buyer,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-minimal-bundle-reject",
                "pointer": minimal_ebfab_pointer,
                "bundle": minimal_ebfab,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-incomplete-binding-reject",
                "pointer": ebfab_pointer,
                "bundle": ebfab_buyer,
                "binding": incomplete_binding,
                "want": {"ok": False},
            },
        ],
    }


def encoded_fixture():
    return (json.dumps(generate(), indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = encoded_fixture()
    if args.write:
        FIXTURE.write_bytes(generated)
        print(f"wrote {FIXTURE.relative_to(ROOT)}")
        return 0
    if not FIXTURE.exists() or FIXTURE.read_bytes() != generated:
        print(f"{FIXTURE.relative_to(ROOT)} is stale; run this script with --write", file=sys.stderr)
        return 1
    print(f"verified {FIXTURE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
