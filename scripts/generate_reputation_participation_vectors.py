#!/usr/bin/env python3
"""Generate DACS-5 v0.7 signed-participation and rating-admission vectors."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "reputation-participation-admission-v0.7.json"
)
SET_NAME = "reputation-participation-admission-v0.7"
SPEC = "DACS-5 v0.7 §10.3.2/§10.5 SPA-1..SPA-8 signed participation and rating admission"
PARTICIPATION_DOMAIN = "dacs-participation-admission:v1:"
RATING_DOMAIN = "dacs-rating:v1:"

JOB = "01J00000000000000000000000"
OTHER_JOB = "01J00000000000000000000001"


def private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def claim_for(key: Ed25519PrivateKey) -> str:
    return "key:" + key.public_key().public_bytes_raw().hex()


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def hash_hex(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sign_component(unsigned: dict, key: Ed25519PrivateKey, signer: str, domain: str) -> dict:
    payload = (domain + hash_hex(unsigned)).encode("ascii")
    return {
        **copy.deepcopy(unsigned),
        "signature": {
            "algorithm": "ed25519",
            "signer": signer,
            "value": b64url(key.sign(payload)),
        },
    }


BUYER_KEY = private_key("dacs-373-buyer")
SELLER_KEY = private_key("dacs-373-seller")
OUTSIDER_KEY = private_key("dacs-373-outsider")
BUYER = claim_for(BUYER_KEY)
SELLER = claim_for(SELLER_KEY)
OUTSIDER = claim_for(OUTSIDER_KEY)
LISTING_REF = {"listingId": "listing-a", "version": 1, "contentHash": "44" * 32}
AGREEMENT_REF = {
    "anchor": {"kind": "storage-program", "locator": "storage-program:agreement-a"},
    "contentHash": "55" * 32,
    "signer": SELLER,
}
PARTIES = [
    {"role": "buyer", "primaryClaim": BUYER, "bundleHash": "66" * 32},
    {"role": "seller", "primaryClaim": SELLER, "bundleHash": "77" * 32},
]


def phase(index: int, kind: str) -> dict:
    return {"index": index, "kind": kind, "outcome": "ok"}


def admission_receipt(index: int = 1, *, timestamp: int = 1_500) -> dict:
    return {
        "receiptVersion": "1",
        "substrate": "demos:testnet",
        "logicalAddress": f"dacs5:participation:{JOB}:seller:{index}",
        "nativeAddress": "storage-program:participation-a",
        "contentHash": "88" * 32,
        "transactionRef": {"kind": "demos-tx", "value": "tx-participation-a"},
        "writer": "demos1seller",
        "writerAuthorized": True,
        "nonce": "9",
        "state": "finalized",
        "observationDisposition": "established",
        "blockRef": {"id": "block-15", "height": "15", "timestamp": timestamp},
        "evidenceValid": True,
        "historyDisposition": "canonical",
        "nativeOrder": 15,
    }


def bundle_receipt(*, timestamp: int = 2_100) -> dict:
    return {
        "substrate": "demos:testnet",
        "state": "finalized",
        "observationDisposition": "established",
        "blockRef": {"id": "block-21", "height": "21", "timestamp": timestamp},
        "evidenceValid": True,
    }


def obligation(kind: str) -> tuple[str, str]:
    if kind == "vet-credentials":
        return "vet-pending", "present-credentials"
    if kind.startswith("negotiate-"):
        return "negotiate-pending", "respond-to-negotiation"
    if kind.startswith("commit-"):
        return "commit-pending", "co-sign-agreement"
    if kind.startswith("pay-"):
        return "settle-pending", "authorize-payment"
    if kind.startswith("deliver-"):
        return "settle-pending", "deliver"
    raise ValueError(kind)


def one_sided_input(
    *,
    pipeline: list[str] | None = None,
    phase_index: int = 1,
) -> dict:
    effective = pipeline or ["vet-credentials", "negotiate-rfq"]
    kind = effective[phase_index]
    pending_state, owed_action = obligation(kind)
    prefix = [phase(i, item) for i, item in enumerate(effective[:phase_index])]
    deadline = 2_000
    timeout = {
        "pendingState": pending_state,
        "phaseIndex": phase_index,
        "phaseKind": kind,
        "obligorRole": "seller",
        "owedAction": owed_action,
        "deadline": deadline,
        "deadlinePolicy": "obligor-admitted-absolute-consensus-deadline",
        "deadlineClock": "sr2-finalized-inclusion-timestamp",
    }
    admission_unsigned = {
        "participationAdmissionVersion": "1",
        "jobId": JOB,
        "listingRef": copy.deepcopy(LISTING_REF),
        "parties": copy.deepcopy(PARTIES),
        "completedPrefix": copy.deepcopy(prefix),
        "phaseIndex": phase_index,
        "phaseKind": kind,
        "pendingState": pending_state,
        "obligorRole": "seller",
        "owedAction": owed_action,
        "deadline": deadline,
        "deadlinePolicy": "obligor-admitted-absolute-consensus-deadline",
        "deadlineClock": "sr2-finalized-inclusion-timestamp",
        "sessionNonce": "aa" * 32,
        "admittedAt": 99_999_999,
    }
    bundle = {
        "bundleType": "FaultAttestationBundle",
        "jobId": JOB,
        "listingRef": copy.deepcopy(LISTING_REF),
        "parties": copy.deepcopy(PARTIES),
        "phaseSummary": copy.deepcopy(prefix),
        "outcome": "aborted-by-other",
        "anchoredByRole": "buyer",
        "verifiedSignerRoles": ["buyer"],
        "faultedParty": "seller",
        "timeout": copy.deepcopy(timeout),
        "windowReceipt": bundle_receipt(),
    }
    if kind.startswith("commit-"):
        admission_unsigned["proposedAgreementHash"] = "99" * 32
    if kind.startswith("pay-") or kind.startswith("deliver-"):
        bundle["agreementRef"] = copy.deepcopy(AGREEMENT_REF)
        admission_unsigned["agreementRef"] = copy.deepcopy(AGREEMENT_REF)
    admission = sign_component(admission_unsigned, SELLER_KEY, SELLER, PARTICIPATION_DOMAIN)
    receipt = admission_receipt(phase_index)
    receipt["contentHash"] = hash_hex(admission)
    return {
        "mode": "one-sided-blame",
        "currentProfile": True,
        "authoritativeAbsenceValid": True,
        "listing": {
            "verified": True,
            "listingRef": copy.deepcopy(LISTING_REF),
            "effectivePipeline": copy.deepcopy(effective),
        },
        "bundle": bundle,
        "participationEvidence": {
            "admissionRef": {
                "anchor": {
                    "kind": "storage-program",
                    "locator": receipt["nativeAddress"],
                },
                "contentHash": receipt["contentHash"],
                "signer": SELLER,
            },
            "admission": admission,
            "noncePreviouslyUsedFor": None,
            "admissionReceipt": copy.deepcopy(receipt),
            "admissionReceiptHistory": [copy.deepcopy(receipt)],
        },
    }


def rating_input() -> dict:
    pipeline = ["vet-credentials", "negotiate-fixed-price", "commit-agreement", "rate"]
    rating_unsigned = {
        "ratingVersion": "1",
        "jobId": JOB,
        "rater": BUYER,
        "target": SELLER,
        "targetRole": "seller",
        "value": 1,
        "ratedAt": 2_200,
    }
    rating = sign_component(rating_unsigned, BUYER_KEY, BUYER, RATING_DOMAIN)
    rating_ref = {
        "anchor": {"kind": "storage-program", "locator": "storage-program:rating-a"},
        "contentHash": hash_hex(rating),
        "signer": BUYER,
    }
    return {
        "mode": "rating",
        "currentProfile": True,
        "listing": {
            "verified": True,
            "listingRef": copy.deepcopy(LISTING_REF),
            "effectivePipeline": pipeline,
        },
        "bundle": {
            "jobId": JOB,
            "listingRef": copy.deepcopy(LISTING_REF),
            "parties": copy.deepcopy(PARTIES),
            "outcome": "completed",
            "fullySigned": True,
            "phaseSummary": [phase(i, kind) for i, kind in enumerate(pipeline)],
            "ratingRefs": [copy.deepcopy(rating_ref)],
        },
        "ratingRef": copy.deepcopy(rating_ref),
        "rating": rating,
    }


def resign_admission(data: dict, *, key: Ed25519PrivateKey = SELLER_KEY,
                     signer: str = SELLER) -> None:
    evidence = data["participationEvidence"]
    unsigned = copy.deepcopy(evidence["admission"])
    unsigned.pop("signature", None)
    admission = sign_component(unsigned, key, signer, PARTICIPATION_DOMAIN)
    evidence["admission"] = admission
    content_hash = hash_hex(admission)
    evidence["admissionRef"]["contentHash"] = content_hash
    evidence["admissionRef"]["signer"] = signer
    evidence["admissionReceipt"]["contentHash"] = content_hash
    for receipt in evidence["admissionReceiptHistory"]:
        receipt["contentHash"] = content_hash


def resign_rating(data: dict, *, key: Ed25519PrivateKey = BUYER_KEY,
                  signer: str = BUYER) -> None:
    unsigned = copy.deepcopy(data["rating"])
    unsigned.pop("signature", None)
    rating = sign_component(unsigned, key, signer, RATING_DOMAIN)
    old_ref = copy.deepcopy(data["ratingRef"])
    data["rating"] = rating
    data["ratingRef"]["contentHash"] = hash_hex(rating)
    data["ratingRef"]["signer"] = signer
    data["bundle"]["ratingRefs"] = [
        copy.deepcopy(data["ratingRef"]) if ref == old_ref else ref
        for ref in data["bundle"].get("ratingRefs", [])
    ]


def want(*, admitted: bool, blame: bool = False, rating: bool = False,
         external: bool = False) -> dict:
    return {
        "reputationDisposition": "admitted" if admitted else "excluded",
        "oneSidedBlame": blame,
        "ratingCounted": rating,
        "externalAdmissionConsumed": external,
    }


def vector(name: str, expected: str, note: str, data: dict, result: dict) -> dict:
    return {"name": name, "expected": expected, "note": note, "input": data, "want": result}


def changed(base: dict, mutate) -> dict:
    item = copy.deepcopy(base)
    mutate(item)
    return item


def rating_changed(base: dict, mutate, *, resign: bool = False,
                   key: Ed25519PrivateKey = BUYER_KEY, signer: str = BUYER) -> dict:
    item = changed(base, mutate)
    if resign:
        resign_rating(item, key=key, signer=signer)
    return item


def build_vectors() -> list[dict]:
    base = one_sided_input()
    admitted_blame = want(admitted=True, blame=True, external=True)
    excluded = want(admitted=False)
    vectors = [
        vector("spa-valid-negotiate-obligation", "pass", "exact target-signed negotiate obligation admits one-sided timeout blame", base, admitted_blame),
        vector("spa-valid-vet-obligation", "pass", "an index-zero vet obligation has an empty authenticated completed prefix", one_sided_input(pipeline=["vet-credentials"], phase_index=0), admitted_blame),
        vector("spa-valid-commit-obligation", "pass", "commit admission binds the proposed agreement hash", one_sided_input(pipeline=["vet-credentials", "negotiate-fixed-price", "commit-agreement"], phase_index=2), admitted_blame),
        vector("spa-valid-payment-obligation", "pass", "settle payment admission binds the committed agreement", one_sided_input(pipeline=["vet-credentials", "negotiate-fixed-price", "commit-agreement", "pay-dem"], phase_index=3), admitted_blame),
        vector("spa-valid-delivery-obligation", "pass", "settle delivery admission binds prior payment and committed agreement", one_sided_input(pipeline=["vet-credentials", "negotiate-fixed-price", "commit-agreement", "pay-dem", "deliver-storage-program"], phase_index=4), admitted_blame),
    ]

    self_admitted = changed(base, lambda x: (
        x["bundle"].update({"verifiedSignerRoles": ["seller"], "anchoredByRole": "seller", "outcome": "aborted-by-self"}),
        x.update({"participationEvidence": None}),
    ))
    vectors.append(vector(
        "spa-single-signed-self-blame-needs-no-external-admission", "pass",
        "the blamed party's exact terminal-bundle signature is its own admission",
        self_admitted, want(admitted=True, blame=True),
    ))

    legacy_with_admission = copy.deepcopy(base)
    legacy_with_admission["bundle"]["bundleType"] = "AttestationBundle"
    legacy_with_admission["bundle"].pop("faultedParty")
    vectors.append(vector(
        "spa-legacy-one-sided-blame-requires-external-admission", "pass",
        "legacy role-relative blame is admitted only through the target's separate SPA",
        legacy_with_admission, admitted_blame,
    ))

    legacy_role_flip = copy.deepcopy(legacy_with_admission)
    legacy_role_flip["bundle"]["verifiedSignerRoles"] = ["seller"]
    legacy_role_flip["participationEvidence"] = None
    vectors.append(vector(
        "spa-legacy-reanchored-signer-cannot-self-admit", "indeterminate",
        "a blamed signer cannot self-admit legacy bytes whose unsigned anchor role changes their meaning",
        legacy_role_flip, excluded,
    ))

    prefix_with_evidence = copy.deepcopy(base)
    prefix_with_evidence["bundle"]["phaseSummary"][0].update({
        "txRefs": [{"kind": "demos-tx", "value": "tx-vet-a"}],
        "attestationRef": {
            "anchor": {"kind": "storage-program", "locator": "vet-record-a"},
            "contentHash": "ab" * 32,
            "signer": SELLER,
        },
    })
    vectors.append(vector(
        "spa-prefix-projection-allows-authenticated-bundle-evidence", "pass",
        "optional bundle phase evidence is outside the three-field participation-prefix projection",
        prefix_with_evidence, admitted_blame,
    ))

    cases = [
        ("spa-never-participant-missing-admission", "indeterminate", "absence alone proves no publication, not participation", lambda x: x.update({"participationEvidence": None})),
        ("spa-unqualified-bundle-absence", "indeterminate", "participation does not replace authoritative bundle absence", lambda x: x.update({"authoritativeAbsenceValid": False})),
        ("spa-invalid-admission-signature", "fail", "a forged admission cannot establish participation", lambda x: x["participationEvidence"]["admission"]["signature"].update({"value": "A" * 86})),
        ("spa-wrong-admission-signer", "fail", "the waiting party cannot sign for the alleged obligor", lambda x: None),
        ("spa-wrong-job-replay", "fail", "an admission from another job cannot be replayed", lambda x: x["participationEvidence"]["admission"].update({"jobId": OTHER_JOB})),
        ("spa-wrong-listing", "fail", "an admission for another listing cannot be rebound", lambda x: x["participationEvidence"]["admission"]["listingRef"].update({"contentHash": "cc" * 32})),
        ("spa-roster-primary-claim-mismatch", "fail", "the admitted roster must equal the terminal bundle roster", lambda x: x["participationEvidence"]["admission"]["parties"][1].update({"primaryClaim": OUTSIDER})),
        ("spa-roster-bundle-hash-mismatch", "fail", "identity bundle hashes are part of the exact roster", lambda x: x["participationEvidence"]["admission"]["parties"][1].update({"bundleHash": "dd" * 32})),
        ("spa-roster-order-noncanonical", "fail", "the admission roster has one canonical order", lambda x: x["participationEvidence"]["admission"].update({"parties": list(reversed(x["participationEvidence"]["admission"]["parties"]))})),
        ("spa-wrong-obligor-role", "fail", "an admission cannot be used to blame another role", lambda x: x["participationEvidence"]["admission"].update({"obligorRole": "buyer"})),
        ("spa-wrong-deadline", "fail", "the bundle timeout and signed admission must name the same deadline", lambda x: x["bundle"]["timeout"].update({"deadline": 2_001})),
        ("spa-wrong-deadline-policy", "fail", "an unregistered clock policy cannot replace the obligor-admitted absolute deadline", lambda x: x["participationEvidence"]["admission"].update({"deadlinePolicy": "producer-wall-clock"})),
        ("spa-wrong-action", "fail", "the signed owed action must equal the timeout claim", lambda x: x["participationEvidence"]["admission"].update({"owedAction": "co-sign-agreement"})),
        ("spa-wrong-pending-state", "fail", "an active negotiate phase cannot be relabelled commit-pending", lambda x: x["participationEvidence"]["admission"].update({"pendingState": "commit-pending"})),
        ("spa-phase-never-active", "fail", "a phase outside the authenticated effective pipeline was never due", lambda x: x["participationEvidence"]["admission"].update({"phaseIndex": 2})),
        ("spa-wrong-phase-kind", "fail", "phase kind must match the authenticated pipeline at the exact index", lambda x: x["participationEvidence"]["admission"].update({"phaseKind": "commit-agreement"})),
        ("spa-incomplete-completed-prefix", "fail", "the active-phase acknowledgement cannot omit a prior phase", lambda x: x["participationEvidence"]["admission"].update({"completedPrefix": []})),
        ("spa-prefix-contradicts-bundle", "fail", "the admitted prefix must match the terminal bundle's phase facts", lambda x: x["bundle"].update({"phaseSummary": []})),
        ("spa-pay-alternative-is-not-active-handler", "fail", "listing-only pay-alternative cannot be admitted as an executable obligation", lambda x: (x["listing"].update({"effectivePipeline": ["vet-credentials", "pay-alternative"]}), x["participationEvidence"]["admission"].update({"phaseKind": "pay-alternative", "pendingState": "settle-pending", "owedAction": "authorize-payment"}), x["bundle"]["timeout"].update({"phaseKind": "pay-alternative", "pendingState": "settle-pending", "owedAction": "authorize-payment"}))),
        ("spa-commit-missing-proposed-agreement-hash", "fail", "commit admission must identify the exact proposed artifact", lambda x: x["participationEvidence"]["admission"].pop("proposedAgreementHash", None)),
        ("spa-settle-wrong-agreement-ref", "fail", "settle admission cannot borrow another agreement", lambda x: x["participationEvidence"]["admission"]["agreementRef"].update({"contentHash": "ee" * 32})),
        ("spa-invalid-session-nonce", "fail", "the session nonce must be exactly 32 lowercase-hex bytes", lambda x: x["participationEvidence"]["admission"].update({"sessionNonce": "AA" * 32})),
        ("spa-observed-cross-session-nonce-reuse", "fail", "an observed signer nonce collision across sessions rejects replay", lambda x: x["participationEvidence"].update({"noncePreviouslyUsedFor": OTHER_JOB})),
        ("spa-missing-admission-receipt", "indeterminate", "a signature without finalized activation time is non-countable", lambda x: x["participationEvidence"].update({"admissionReceipt": None})),
        ("spa-nonfinal-admission-receipt", "indeterminate", "accepted is not finalized activation evidence", lambda x: x["participationEvidence"]["admissionReceipt"].update({"state": "accepted"})),
        ("spa-admission-receipt-hash-mismatch", "fail", "the receipt must bind the exact admission content hash", lambda x: x["participationEvidence"]["admissionReceipt"].update({"contentHash": "ff" * 32})),
        ("spa-admission-writer-not-obligor", "fail", "the alleged obligor must authorize the admission anchor", lambda x: x["participationEvidence"]["admissionReceipt"].update({"writerAuthorized": False})),
        ("spa-admission-at-deadline-too-late", "fail", "activation admission must finalize strictly before timeout", lambda x: x["participationEvidence"]["admissionReceipt"]["blockRef"].update({"timestamp": 2_000})),
        ("spa-bundle-before-deadline", "fail", "a bundle anchored before deadline cannot prove timeout", lambda x: x["bundle"]["windowReceipt"]["blockRef"].update({"timestamp": 1_999})),
        ("spa-cross-substrate-clock", "indeterminate", "unrelated substrate clocks cannot establish the deadline interval", lambda x: x["bundle"]["windowReceipt"].update({"substrate": "evm:1"})),
        ("spa-unorderable-admission-history", "indeterminate", "conflicting admission receipt history cannot be cherry-picked", lambda x: x["participationEvidence"].update({"admissionReceiptHistory": [{**copy.deepcopy(x["participationEvidence"]["admissionReceipt"]), "historyDisposition": "unorderable"}]})),
        ("spa-unexpected-evidence-on-self-admitted-path", "fail", "unused conditional evidence makes replay non-conforming", lambda x: x["bundle"].update({"verifiedSignerRoles": ["seller"], "anchoredByRole": "seller", "outcome": "aborted-by-self"})),
    ]
    for name, expected, note, mutate in cases:
        source = base
        if name == "spa-commit-missing-proposed-agreement-hash":
            source = one_sided_input(pipeline=["vet-credentials", "negotiate-fixed-price", "commit-agreement"], phase_index=2)
        elif name == "spa-settle-wrong-agreement-ref":
            source = one_sided_input(pipeline=["vet-credentials", "negotiate-fixed-price", "commit-agreement", "pay-dem"], phase_index=3)
        item = changed(source, mutate)
        signed_field_mutations = {
            "spa-wrong-job-replay",
            "spa-wrong-listing",
            "spa-roster-primary-claim-mismatch",
            "spa-roster-bundle-hash-mismatch",
            "spa-roster-order-noncanonical",
            "spa-wrong-obligor-role",
            "spa-wrong-deadline-policy",
            "spa-wrong-action",
            "spa-wrong-pending-state",
            "spa-phase-never-active",
            "spa-wrong-phase-kind",
            "spa-incomplete-completed-prefix",
            "spa-pay-alternative-is-not-active-handler",
            "spa-commit-missing-proposed-agreement-hash",
            "spa-settle-wrong-agreement-ref",
            "spa-invalid-session-nonce",
        }
        if name == "spa-wrong-admission-signer":
            resign_admission(item, key=BUYER_KEY, signer=BUYER)
        elif name in signed_field_mutations:
            resign_admission(item)
        vectors.append(vector(name, expected, note, item, excluded))

    advisory = changed(base, lambda x: x["participationEvidence"]["admission"].update({"admittedAt": -9_999_999}))
    resign_admission(advisory)
    vectors.append(vector(
        "spa-admitted-at-is-advisory", "pass",
        "producer time cannot override two authenticated receipt timestamps",
        advisory, admitted_blame,
    ))

    rate = rating_input()
    counted = want(admitted=True, rating=True)
    vectors += [
        vector("spa-rating-valid-buyer-to-seller", "pass", "a completed authenticated rate phase admits an exact seller rating", rate, counted),
        vector("spa-rating-valid-seller-to-buyer", "pass", "the inverse direction uses the same exact role gate", rating_changed(rate, lambda x: x["rating"].update({"rater": SELLER, "target": BUYER, "targetRole": "buyer"}), resign=True, key=SELLER_KEY, signer=SELLER), counted),
        vector("spa-rating-on-abort", "fail", "ordinary ratings cannot be attached to an aborted session", changed(rate, lambda x: x["bundle"].update({"outcome": "aborted-by-other", "fullySigned": False})), excluded),
        vector("spa-rating-on-failure", "fail", "ordinary ratings cannot be attached to a failed session", changed(rate, lambda x: x["bundle"].update({"outcome": "failed-counterparty"})), excluded),
        vector("spa-rating-completed-bundle-not-fully-signed", "fail", "completed outcome alone does not prove target participation", changed(rate, lambda x: x["bundle"].update({"fullySigned": False})), excluded),
        vector("spa-rating-phase-not-in-listing", "fail", "a producer cannot invent a rate phase", changed(rate, lambda x: x["listing"].update({"effectivePipeline": x["listing"]["effectivePipeline"][:-1]})), excluded),
        vector("spa-rating-phase-failed", "fail", "a failed rate phase is not an eligible completed phase", changed(rate, lambda x: x["bundle"]["phaseSummary"][-1].update({"outcome": "fail"})), excluded),
        vector("spa-rating-phase-wrong-index", "fail", "the bundle rate entry must occupy the listing's exact index", changed(rate, lambda x: x["bundle"]["phaseSummary"][-1].update({"index": 2})), excluded),
        vector("spa-rating-reference-not-in-bundle", "fail", "a loose rating reference is not admitted", changed(rate, lambda x: x["bundle"].update({"ratingRefs": []})), excluded),
        vector("spa-rating-invalid-signature", "fail", "a forged rating is excluded", changed(rate, lambda x: x["rating"]["signature"].update({"value": "A" * 86})), excluded),
        vector("spa-rating-wrong-job", "fail", "a rating cannot cross sessions", rating_changed(rate, lambda x: x["rating"].update({"jobId": OTHER_JOB}), resign=True), excluded),
        vector("spa-rating-non-roster-target", "fail", "an invented target is excluded", rating_changed(rate, lambda x: x["rating"].update({"target": OUTSIDER}), resign=True), excluded),
        vector("spa-rating-wrong-target-role", "fail", "targetRole must equal the target's exact authenticated role", rating_changed(rate, lambda x: x["rating"].update({"targetRole": "buyer"}), resign=True), excluded),
        vector("spa-rating-non-roster-rater", "fail", "only an authenticated session party may rate", rating_changed(rate, lambda x: x["rating"].update({"rater": OUTSIDER}), resign=True, key=OUTSIDER_KEY, signer=OUTSIDER), excluded),
        vector("spa-rating-self-rating", "fail", "a party cannot rate itself", rating_changed(rate, lambda x: x["rating"].update({"target": BUYER, "targetRole": "buyer"}), resign=True), excluded),
        vector("spa-rating-listing-unavailable", "indeterminate", "unavailable phase authority cannot be treated as a completed rate phase", changed(rate, lambda x: x["listing"].update({"verified": False})), excluded),
    ]
    return vectors


def document() -> dict:
    vectors = build_vectors()
    encoded = json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()
    return {
        "set": SET_NAME,
        "spec": SPEC,
        "decisionModel": "pass admits current reputation; fail or indeterminate excludes without alternative blame",
        "inputModel": "post-reconciliation bundle plus authenticated Listing/effective-pipeline projection, exact signed participation/rating artifact, and authenticated SR-2 receipt context",
        "hash": hashlib.sha256(encoded).hexdigest(),
        "count": len(vectors),
        "vectors": vectors,
    }


def render_document(data: dict) -> str:
    lines = ["{"]
    for key, value in ((key, value) for key, value in data.items() if key != "vectors"):
        lines.append(f"  {json.dumps(key)}: {json.dumps(value, ensure_ascii=False)},")
    lines.append('  "vectors": [')
    for index, item in enumerate(data["vectors"]):
        comma = "," if index + 1 < len(data["vectors"]) else ""
        lines.append("    " + json.dumps(item, separators=(", ", ": "), ensure_ascii=False) + comma)
    lines.extend(["  ]", "}"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = render_document(document())
    if args.write:
        OUTPUT.write_text(rendered, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
        print(f"ERROR: {OUTPUT.relative_to(ROOT)} is stale; run this script with --write")
        return 1
    print(f"participation-admission vectors OK ({len(build_vectors())} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
