#!/usr/bin/env python3
"""Generate DACS-3 v0.6 sealed-auction completeness vectors."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from decimal import Decimal, InvalidOperation
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize as jcs_canonicalize


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/vectors/security/sealed-auction-completeness-v0.6.json"
RECORD_DOMAIN = "dacs-sealed-auction-record:v1:"
RECEIPT_DOMAIN = "dacs-sealed-selection-receipt:v1:"
AGREEMENT_DOMAIN = "dacs-sealed-selection-agreement:v1:"
BINDING_DOMAIN = "test-candidate-set-proof:v1:"
JOB_ID = "01JZZZZZZZZZZZZZZZZZZZZZZZ"
LISTING_REF = {
    "listingId": "complete-sealed-demo",
    "version": 1,
    "contentHash": "91" * 32,
}
PHASE_INDEX = 1
COMMIT_DEADLINE = 2_000_000_000_000
REVEAL_DEADLINE = COMMIT_DEADLINE + 120_000
CURRENT_STATE = {
    "id": "state-200",
    "height": "200",
    "timestamp": REVEAL_DEADLINE + 5_000,
}
STALE_STATE = {
    "id": "state-199",
    "height": "199",
    "timestamp": REVEAL_DEADLINE + 1_000,
}


def seed(label: str) -> bytes:
    return hashlib.sha256(("DACS sealed completeness v1 " + label).encode()).digest()


KEYS = {
    name: Ed25519PrivateKey.from_private_bytes(seed(name))
    for name in ("bidder-a", "bidder-b", "bidder-c", "publisher", "orchestrator", "binding")
}
CLAIMS = {
    name: "did:demos:agent:" + hashlib.sha256(("claim " + name).encode()).hexdigest()
    for name in ("bidder-a", "bidder-b", "bidder-c", "publisher", "orchestrator")
}
BIDDER_NAMES = ("bidder-a", "bidder-b", "bidder-c")


def canonical(value: object) -> bytes:
    return jcs_canonicalize(value).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def vector_hash(vectors: list[dict]) -> str:
    raw = json.dumps(vectors, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def public_key(name: str) -> str:
    raw = KEYS[name].public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64url(raw)


def unsigned(value: dict) -> dict:
    return {key: item for key, item in value.items() if key not in {"signature", "signatures"}}


def sign_artifact(value: dict, key_name: str, domain: str, *, plural: bool = False) -> dict:
    value = copy.deepcopy(value)
    content_hash = digest(unsigned(value))
    signature = {
        "algorithm": "ed25519",
        "signer" if not plural else "party": CLAIMS[key_name],
        "value": b64url(KEYS[key_name].sign((domain + content_hash).encode("ascii"))),
    }
    if plural:
        value.setdefault("signatures", []).append(signature)
    else:
        value["signature"] = signature
    return value


def attestation_ref(kind: str, locator: str, content_hash: str, signer: str | None = None) -> dict:
    result = {
        "anchor": {"kind": kind, "locator": locator},
        "contentHash": content_hash,
    }
    if signer is not None:
        result["signer"] = signer
    return result


def bid_hash(bid: dict, salt: bytes) -> str:
    bid_digest = hashlib.sha256(canonical(bid)).digest()
    return hashlib.sha256(RECORD_DOMAIN.replace("auction-record", "bid").encode() + bid_digest + salt).hexdigest()


def logical_address(kind: str, bidder_claim: str, value: str) -> str:
    encoded = bidder_claim.replace("%", "%25").replace(":", "%3A")
    return f"dacs3:auction:{JOB_ID}:{kind}:{encoded}:{value}"


def make_record_pair(name: str, amount: str, commit_time: int, reveal_time: int, ordinal: int) -> tuple[list[dict], dict]:
    claim = CLAIMS[name]
    bid = {
        "price": {"amount": amount, "currency": "USD"},
        "deliverable": {"deliverableType": "digital", "hash": "ab" * 32},
    }
    salt = seed("salt " + name)
    commitment = bid_hash(bid, salt)
    commit = sign_artifact({
        "sealedAuctionRecordVersion": "1",
        "recordKind": "commit",
        "jobId": JOB_ID,
        "listingRef": LISTING_REF,
        "phaseIndex": PHASE_INDEX,
        "bidderClaim": claim,
        "bidHash": commitment,
        "createdAt": commit_time - 50,
    }, name, RECORD_DOMAIN)
    commit_hash = digest(unsigned(commit))
    commit_locator = "stor-commit-" + commit_hash[:24]
    commit_ref = attestation_ref("storage-program", commit_locator, commit_hash, claim)
    reveal = sign_artifact({
        "sealedAuctionRecordVersion": "1",
        "recordKind": "reveal",
        "jobId": JOB_ID,
        "listingRef": LISTING_REF,
        "phaseIndex": PHASE_INDEX,
        "bidderClaim": claim,
        "bidHash": commitment,
        "commitRef": commit_ref,
        "bid": bid,
        "salt": b64url(salt),
        "createdAt": reveal_time - 50,
    }, name, RECORD_DOMAIN)
    reveal_hash = digest(unsigned(reveal))
    reveal_locator = "stor-reveal-" + reveal_hash[:24]
    reveal_ref = attestation_ref("storage-program", reveal_locator, reveal_hash, claim)

    def entry(record: dict, ref: dict, timestamp: int, suffix: int) -> dict:
        record_hash = ref["contentHash"]
        return {
            "recordRef": ref,
            "anchorReceipt": {
                "receiptVersion": "1",
                "substrate": "test-bft",
                "finalityProfile": "test-bft-final",
                "logicalAddress": logical_address(record["recordKind"], claim, commitment),
                "nativeAddress": ref["anchor"]["locator"],
                "contentHash": record_hash,
                "transactionRef": {"kind": "test-tx", "value": "tx-" + record_hash[:20]},
                "writer": claim,
                "nonce": str(ordinal * 2 + suffix),
                "state": "finalized",
                "observationDisposition": "established",
                "observedAt": timestamp + 100,
                "blockRef": {
                    "id": "block-" + str(timestamp),
                    "height": str(100 + ordinal * 2 + suffix),
                    "timestamp": timestamp,
                },
                "evidence": {"kind": "test-finality", "value": "proof-" + record_hash[:20]},
            },
            "orderKey": f"{timestamp:016d}:{ordinal:04d}:{suffix}",
        }

    entries = [entry(commit, commit_ref, commit_time, 0), entry(reveal, reveal_ref, reveal_time, 1)]
    return entries, {commit_hash: commit, reveal_hash: reveal}


def base_material(prices: tuple[str, str, str] = ("100", "80", "120"), *, equal_commit_time: bool = False) -> tuple[list[dict], dict]:
    entries: list[dict] = []
    records: dict[str, dict] = {}
    for index, (name, amount) in enumerate(zip(BIDDER_NAMES, prices), start=1):
        commit_time = COMMIT_DEADLINE - (30_000 - index * 2_000)
        if equal_commit_time and name in {"bidder-a", "bidder-b"}:
            commit_time = COMMIT_DEADLINE - 20_000
        pair_entries, pair_records = make_record_pair(
            name,
            amount,
            commit_time,
            COMMIT_DEADLINE + 20_000 + index * 2_000,
            index,
        )
        entries.extend(pair_entries)
        records.update(pair_records)
    entries.sort(key=lambda item: (item["orderKey"], item["recordRef"]["contentHash"]))
    return entries, records


def binding_payload(collection_prefix: str, evidence: dict) -> dict:
    return {
        "collectionPrefix": collection_prefix,
        "finalizedState": evidence["finalizedState"],
        "recordSetHash": evidence["recordSetHash"],
        "recordCount": evidence["recordCount"],
    }


def completeness_evidence(entries: list[dict], collection_prefix: str, state: dict = CURRENT_STATE) -> dict:
    evidence = {
        "substrate": "test-bft",
        "finalizedState": copy.deepcopy(state),
        "recordSetHash": digest(entries),
        "recordCount": str(len(entries)),
        "proof": {"kind": "test-complete-prefix", "value": ""},
    }
    proof = KEYS["binding"].sign((BINDING_DOMAIN + digest(binding_payload(collection_prefix, evidence))).encode("ascii"))
    evidence["proof"]["value"] = b64url(proof)
    return evidence


def decode_salt(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def derive(entries: list[dict], records: dict, *, selection_rule: str, reserve: str | None = None) -> tuple[list[dict], list[dict], dict | None]:
    record_decisions: list[dict] = []
    valid_commits: dict[str, list[tuple[dict, dict]]] = {}
    valid_reveals: dict[str, list[tuple[dict, dict]]] = {}
    for entry in entries:
        record_hash = entry["recordRef"]["contentHash"]
        record = records.get(record_hash)
        reason = None
        disposition = None
        if not isinstance(record, dict):
            reason = "malformed-record"
        else:
            signature = record.get("signature", {})
            expected_name = next((name for name, claim in CLAIMS.items() if claim == record.get("bidderClaim")), None)
            if expected_name not in BIDDER_NAMES or signature.get("signer") != record.get("bidderClaim"):
                reason = "bad-signature"
            else:
                try:
                    KEYS[expected_name].public_key().verify(
                        base64.urlsafe_b64decode(signature["value"] + "=" * (-len(signature["value"]) % 4)),
                        (RECORD_DOMAIN + digest(unsigned(record))).encode("ascii"),
                    )
                except Exception:
                    reason = "bad-signature"
            if reason is None:
                want_address = logical_address(record.get("recordKind", ""), record["bidderClaim"], record["bidHash"])
                if entry["anchorReceipt"].get("logicalAddress") != want_address:
                    reason = "wrong-address"
                elif entry["anchorReceipt"].get("state") != "finalized":
                    reason = "unfinalized"
                else:
                    timestamp = entry["anchorReceipt"]["blockRef"]["timestamp"]
                    if record["recordKind"] == "commit" and timestamp > COMMIT_DEADLINE:
                        reason = "late-commit"
                    elif record["recordKind"] == "reveal" and timestamp > REVEAL_DEADLINE:
                        reason = "late-reveal"
                    elif record["recordKind"] == "commit":
                        disposition = "admitted-commit"
                        valid_commits.setdefault(record["bidderClaim"], []).append((entry, record))
                    elif record["recordKind"] == "reveal":
                        disposition = "admitted-reveal"
                        valid_reveals.setdefault(record["bidderClaim"], []).append((entry, record))
                    else:
                        reason = "malformed-record"
        record_decisions.append({
            "recordContentHash": record_hash,
            "disposition": disposition or "excluded",
            **({"reason": reason} if reason else {}),
        })

    bid_decisions: list[dict] = []
    eligible: list[tuple[dict, dict, dict, dict]] = []
    decision_index = {
        decision["recordContentHash"]: index
        for index, decision in enumerate(record_decisions)
    }
    for bidder in sorted({CLAIMS[name] for name in BIDDER_NAMES}):
        commits = valid_commits.get(bidder, [])
        if not commits:
            bid_decisions.append({"bidderClaim": bidder, "disposition": "excluded", "reason": "no-authoritative-commit"})
            continue
        commits.sort(key=lambda pair: (pair[0]["anchorReceipt"]["blockRef"]["timestamp"], pair[1]["bidHash"]))
        commit_entry, commit = commits[0]
        for later_entry, _ in commits[1:]:
            record_decisions[decision_index[later_entry["recordRef"]["contentHash"]]] = {
                "recordContentHash": later_entry["recordRef"]["contentHash"],
                "disposition": "excluded",
                "reason": "non-authoritative-commit",
            }
        commit_ref = commit_entry["recordRef"]
        bidder_reveals = sorted(
            valid_reveals.get(bidder, []),
            key=lambda pair: (
                pair[0]["anchorReceipt"]["blockRef"]["timestamp"],
                pair[0]["orderKey"],
                pair[0]["recordRef"]["contentHash"],
            ),
        )
        matching_reveals = []
        for candidate in bidder_reveals:
            reveal = candidate[1]
            try:
                recomputed = bid_hash(reveal["bid"], decode_salt(reveal["salt"]))
            except Exception:
                continue
            if reveal.get("commitRef") == commit_ref and reveal.get("bidHash") == commit["bidHash"] == recomputed:
                matching_reveals.append(candidate)
        reveal_pair = matching_reveals[0] if matching_reveals else None
        for candidate in bidder_reveals:
            if candidate is reveal_pair:
                continue
            content_hash = candidate[0]["recordRef"]["contentHash"]
            record_decisions[decision_index[content_hash]] = {
                "recordContentHash": content_hash,
                "disposition": "duplicate" if candidate in matching_reveals else "excluded",
                "reason": "duplicate-reveal" if candidate in matching_reveals else "bid-hash-mismatch",
            }
        if reveal_pair is None:
            bid_decisions.append({
                "bidderClaim": bidder,
                "authoritativeCommitRef": commit_ref,
                "disposition": "excluded",
                "reason": "no-valid-reveal",
            })
            continue
        reveal_entry, reveal = reveal_pair
        price = reveal["bid"]["price"]
        reason = None
        try:
            amount = Decimal(price["amount"])
        except (InvalidOperation, KeyError, TypeError):
            amount = Decimal(0)
        if price.get("currency") != "USD":
            reason = "currency-mismatch"
        elif amount <= 0:
            reason = "non-positive-price"
        elif reserve is not None and ((selection_rule == "lowest-price" and amount > Decimal(reserve)) or (selection_rule == "highest-price" and amount < Decimal(reserve))):
            reason = "reserve-price"
        decision = {
            "bidderClaim": bidder,
            "authoritativeCommitRef": commit_ref,
            "revealRef": reveal_entry["recordRef"],
            "bidContentHash": digest(reveal["bid"]),
            "price": price,
            "disposition": "excluded" if reason else "eligible",
            **({"reason": reason} if reason else {}),
        }
        bid_decisions.append(decision)
        if reason is None:
            eligible.append((commit_entry, commit, reveal_entry, reveal))

    if selection_rule not in {"lowest-price", "highest-price"} or not eligible:
        return record_decisions, bid_decisions, None
    eligible.sort(key=lambda value: (
        Decimal(value[3]["bid"]["price"]["amount"]) * (1 if selection_rule == "lowest-price" else -1),
        value[0]["anchorReceipt"]["blockRef"]["timestamp"],
        value[1]["bidHash"],
    ))
    commit_entry, commit, reveal_entry, reveal = eligible[0]
    winner = {
        "bidderClaim": commit["bidderClaim"],
        "authoritativeCommitRef": commit_entry["recordRef"],
        "revealRef": reveal_entry["recordRef"],
        "bidContentHash": digest(reveal["bid"]),
        "price": reveal["bid"]["price"],
        "commitAnchorTimestamp": commit_entry["anchorReceipt"]["blockRef"]["timestamp"],
        "bidHash": commit["bidHash"],
    }
    return record_decisions, bid_decisions, winner


def signed_receipt(entries: list[dict], records: dict, *, selection_rule: str = "lowest-price", state: dict = CURRENT_STATE) -> dict:
    collection_prefix = "dacs3:auction:" + JOB_ID
    record_decisions, bid_decisions, winner = derive(entries, records, selection_rule=selection_rule)
    receipt = {
        "sealedSelectionReceiptVersion": "1",
        "jobId": JOB_ID,
        "listingRef": LISTING_REF,
        "phaseIndex": PHASE_INDEX,
        "phaseKind": "negotiate-sealed-envelope-procurement-complete",
        "candidateSetBinding": {
            "bindingId": "test-complete-log",
            "bindingVersion": "1",
            "definitionRef": attestation_ref("storage-program", "stor-test-binding", "77" * 32, CLAIMS["publisher"]),
        },
        "collectionPrefix": collection_prefix,
        "selectionRule": selection_rule,
        "entries": copy.deepcopy(entries),
        "completenessEvidence": completeness_evidence(entries, collection_prefix, state),
        "recordDecisions": record_decisions,
        "bidDecisions": bid_decisions,
        **({"winner": winner} if winner else {}),
        "createdAt": REVEAL_DEADLINE + 6_000,
    }
    return sign_artifact(receipt, "orchestrator", RECEIPT_DOMAIN)


def signed_agreement(receipt: dict) -> dict:
    winner = receipt.get("winner") or {
        "bidderClaim": CLAIMS["bidder-a"],
        "price": {"amount": "100", "currency": "USD"},
    }
    receipt_hash = digest(unsigned(receipt))
    agreement = {
        "sealedSelectionAgreementVersion": "1",
        "jobId": JOB_ID,
        "listingRef": LISTING_REF,
        "parties": [
            {
                "role": "buyer",
                "bundleHash": "41" * 32,
                "primaryClaim": CLAIMS["publisher"],
                "vetRecordRef": attestation_ref("storage-program", "stor-vet-publisher", "42" * 32),
            },
            {
                "role": "seller",
                "bundleHash": "43" * 32,
                "primaryClaim": winner["bidderClaim"],
                "vetRecordRef": attestation_ref("storage-program", "stor-vet-winner", "44" * 32),
            },
        ],
        "terms": {
            "deliverable": {"deliverableType": "digital", "hash": "ab" * 32},
            "price": copy.deepcopy(winner["price"]),
            "deadline": REVEAL_DEADLINE + 3_600_000,
            "payoutBindings": [],
        },
        "derivedFromPattern": "sealed-envelope",
        "selectionReceiptRef": attestation_ref(
            "storage-program", "stor-selection-" + receipt_hash[:24], receipt_hash, CLAIMS["orchestrator"]
        ),
        "generatedAt": REVEAL_DEADLINE + 7_000,
        "signatures": [],
    }
    agreement = sign_artifact(agreement, "publisher", AGREEMENT_DOMAIN, plural=True)
    winner_name = next(name for name, claim in CLAIMS.items() if claim == winner["bidderClaim"])
    return sign_artifact(agreement, winner_name, AGREEMENT_DOMAIN, plural=True)


def resign_receipt(receipt: dict) -> dict:
    receipt = unsigned(receipt)
    return sign_artifact(receipt, "orchestrator", RECEIPT_DOMAIN)


def resign_agreement(agreement: dict) -> dict:
    agreement = unsigned(agreement)
    agreement["signatures"] = []
    agreement = sign_artifact(agreement, "publisher", AGREEMENT_DOMAIN, plural=True)
    seller_claim = next(p["primaryClaim"] for p in agreement["parties"] if p["role"] == "seller")
    seller_name = next(name for name, claim in CLAIMS.items() if claim == seller_claim)
    return sign_artifact(agreement, seller_name, AGREEMENT_DOMAIN, plural=True)


def selection_receipt_anchor(receipt: dict) -> dict:
    receipt_hash = digest(unsigned(receipt))
    native_address = "stor-selection-" + receipt_hash[:24]
    return {
        "receiptVersion": "1",
        "substrate": "test-bft",
        "finalityProfile": "test-bft-final",
        "logicalAddress": f"dacs3:selection:{JOB_ID}:{PHASE_INDEX}",
        "nativeAddress": native_address,
        "contentHash": receipt_hash,
        "transactionRef": {"kind": "test-tx", "value": "tx-selection-" + receipt_hash[:16]},
        "writer": CLAIMS["orchestrator"],
        "nonce": "99",
        "state": "finalized",
        "observationDisposition": "established",
        "observedAt": REVEAL_DEADLINE + 6_500,
        "blockRef": {"id": "block-selection", "height": "201", "timestamp": REVEAL_DEADLINE + 6_000},
        "evidence": {"kind": "test-finality", "value": "proof-selection-" + receipt_hash[:16]},
    }


def make_vector(name: str, expected: str, reason: str, entries: list[dict], records: dict, receipt: dict, agreement: dict, **context_overrides) -> dict:
    context = {
        "bindingDefinitionResolved": True,
        "bindingPublicKey": public_key("binding"),
        "latestFinalizedState": copy.deepcopy(CURRENT_STATE),
        "knownConflictingStates": [],
        "recordPublicKeys": {CLAIMS[name]: public_key(name) for name in BIDDER_NAMES},
        "expectedOrchestratorClaim": CLAIMS["orchestrator"],
        "orchestratorPublicKey": public_key("orchestrator"),
        "partyPublicKeys": {
            CLAIMS["publisher"]: public_key("publisher"),
            **{CLAIMS[name]: public_key(name) for name in BIDDER_NAMES},
        },
        "resolvedRecords": copy.deepcopy(records),
        "selectionReceiptAnchor": selection_receipt_anchor(receipt),
    }
    context.update(context_overrides)
    return {
        "name": name,
        "expected": expected,
        "reason": reason,
        "listing": {
            "listingRef": LISTING_REF,
            "publisherClaim": CLAIMS["publisher"],
            "phaseIndex": PHASE_INDEX,
            "phaseKind": "negotiate-sealed-envelope-procurement-complete",
            "parameters": {
                "commitDeadline": COMMIT_DEADLINE,
                "revealWindow": 120,
                "selectionRule": receipt["selectionRule"],
                "candidateSetBinding": receipt["candidateSetBinding"],
                "auctionMode": "procurement",
            },
        },
        "receipt": receipt,
        "agreement": agreement,
        "context": context,
    }


def build() -> dict:
    vectors: list[dict] = []

    entries, records = base_material()
    receipt = signed_receipt(entries, records)
    agreement = signed_agreement(receipt)
    vectors.append(make_vector("complete-lowest-price", "pass", "complete current set selects bidder B", entries, records, receipt, agreement))

    high_receipt = signed_receipt(entries, records, selection_rule="highest-price")
    vectors.append(make_vector("complete-highest-price", "pass", "highest price deterministically selects bidder C", entries, records, high_receipt, signed_agreement(high_receipt)))

    omitted = copy.deepcopy(receipt)
    omitted["entries"] = [entry for entry in omitted["entries"] if entry["recordRef"]["contentHash"] != receipt["winner"]["revealRef"]["contentHash"]]
    omitted = resign_receipt(omitted)
    vectors.append(make_vector("omitted-better-reveal", "fail", "signed receipt cannot omit the winning reveal covered by the complete-set proof", entries, records, omitted, signed_agreement(omitted)))

    stale_entries = [
        entry for entry in entries
        if records[entry["recordRef"]["contentHash"]]["bidderClaim"] != CLAIMS["bidder-b"]
    ]
    stale_records = {entry["recordRef"]["contentHash"]: records[entry["recordRef"]["contentHash"]] for entry in stale_entries}
    stale_receipt = signed_receipt(stale_entries, stale_records, state=STALE_STATE)
    vectors.append(make_vector("selective-discovery-stale-signed-set", "indeterminate", "valid old proof is not current completeness", stale_entries, stale_records, stale_receipt, signed_agreement(stale_receipt)))

    no_proof = copy.deepcopy(receipt)
    no_proof["completenessEvidence"]["proof"]["value"] = ""
    no_proof = resign_receipt(no_proof)
    vectors.append(make_vector("missing-completeness-proof", "indeterminate", "missing binding proof cannot establish a complete set", entries, records, no_proof, signed_agreement(no_proof)))

    vectors.append(make_vector(
        "finalized-fork-conflict", "indeterminate", "unreconciled current finalized views block selection",
        entries, records, receipt, agreement,
        knownConflictingStates=[{"id": "state-200b", "height": "200", "timestamp": CURRENT_STATE["timestamp"]}],
    ))

    unavailable_records = copy.deepcopy(records)
    unavailable_records.pop(receipt["winner"]["revealRef"]["contentHash"])
    vectors.append(make_vector(
        "winning-record-unavailable", "indeterminate", "a complete ref that cannot be resolved cannot be silently excluded",
        entries, records, receipt, agreement, resolvedRecords=unavailable_records,
    ))

    missing_key_context = {CLAIMS[name]: public_key(name) for name in BIDDER_NAMES if name != "bidder-b"}
    vectors.append(make_vector(
        "bidder-key-unavailable", "indeterminate", "unavailable bidder authority blocks rather than improves another rank",
        entries, records, receipt, agreement, recordPublicKeys=missing_key_context,
    ))

    vectors.append(make_vector(
        "binding-definition-unavailable", "indeterminate", "the signed listing binding definition must resolve",
        entries, records, receipt, agreement, bindingDefinitionResolved=False,
    ))

    vectors.append(make_vector(
        "selection-receipt-anchor-unavailable", "indeterminate", "agreement cannot act on an unfinalized or unavailable receipt",
        entries, records, receipt, agreement, selectionReceiptAnchor=None,
    ))

    lying_receipt = copy.deepcopy(receipt)
    a_decision = next(item for item in lying_receipt["bidDecisions"] if item["bidderClaim"] == CLAIMS["bidder-a"])
    a_record = records[a_decision["authoritativeCommitRef"]["contentHash"]]
    lying_receipt["winner"] = {
        "bidderClaim": CLAIMS["bidder-a"],
        "authoritativeCommitRef": a_decision["authoritativeCommitRef"],
        "revealRef": a_decision["revealRef"],
        "bidContentHash": a_decision["bidContentHash"],
        "price": a_decision["price"],
        "commitAnchorTimestamp": next(e["anchorReceipt"]["blockRef"]["timestamp"] for e in entries if e["recordRef"] == a_decision["authoritativeCommitRef"]),
        "bidHash": a_record["bidHash"],
    }
    lying_receipt = resign_receipt(lying_receipt)
    vectors.append(make_vector("signed-lying-winner", "fail", "orchestrator signature cannot replace independent winner recomputation", entries, records, lying_receipt, signed_agreement(lying_receipt)))

    unauthorized_receipt = sign_artifact(unsigned(receipt), "publisher", RECEIPT_DOMAIN)
    vectors.append(make_vector("unauthorized-selection-receipt-signer", "fail", "a valid signature by the listing publisher does not replace session-orchestrator authority", entries, records, unauthorized_receipt, signed_agreement(unauthorized_receipt)))

    bad_ref_agreement = copy.deepcopy(agreement)
    bad_ref_agreement["selectionReceiptRef"]["contentHash"] = "00" * 32
    bad_ref_agreement = resign_agreement(bad_ref_agreement)
    vectors.append(make_vector("agreement-receipt-substitution", "fail", "party signatures do not cure a substituted receipt ref", entries, records, receipt, bad_ref_agreement))

    bad_price_agreement = copy.deepcopy(agreement)
    bad_price_agreement["terms"]["price"]["amount"] = "81"
    bad_price_agreement = resign_agreement(bad_price_agreement)
    vectors.append(make_vector("agreement-winner-price-mismatch", "fail", "agreement price must equal the reproduced winner bid", entries, records, receipt, bad_price_agreement))

    unsupported_first = signed_receipt(entries, records)
    unsupported_first["selectionRule"] = "first-acceptable"
    unsupported_first = resign_receipt(unsupported_first)
    vectors.append(make_vector("first-acceptable-refused", "fail", "complete profile refuses unspecified predicates before execution", entries, records, unsupported_first, signed_agreement(unsupported_first)))

    unsupported_rule = signed_receipt(entries, records)
    unsupported_rule["selectionRule"] = "rule-ref:" + "12" * 32 + ":https://rules.example/select"
    unsupported_rule = resign_receipt(unsupported_rule)
    vectors.append(make_vector("rule-ref-refused", "fail", "complete profile refuses custom runtime semantics before fetch/execution", entries, records, unsupported_rule, signed_agreement(unsupported_rule)))
    vectors.append(make_vector(
        "rule-ref-timeout-refused-before-execution", "fail", "a caller-reported custom runtime timeout is inert because rule-ref is structurally unsupported",
        entries, records, unsupported_rule, signed_agreement(unsupported_rule), untrustedRuleRuntimeOutcome="timeout",
    ))
    vectors.append(make_vector(
        "rule-ref-error-refused-before-execution", "fail", "a caller-reported custom runtime error is inert because rule-ref is structurally unsupported",
        entries, records, unsupported_rule, signed_agreement(unsupported_rule), untrustedRuleRuntimeOutcome="error",
    ))

    late_entries = copy.deepcopy(entries)
    b_reveal_hash = receipt["winner"]["revealRef"]["contentHash"]
    for entry in late_entries:
        if entry["recordRef"]["contentHash"] == b_reveal_hash:
            entry["anchorReceipt"]["blockRef"]["timestamp"] = REVEAL_DEADLINE + 1
            entry["orderKey"] = f"{REVEAL_DEADLINE + 1:016d}:9999:1"
    late_entries.sort(key=lambda item: (item["orderKey"], item["recordRef"]["contentHash"]))
    late_receipt = signed_receipt(late_entries, records)
    vectors.append(make_vector("late-better-reveal-excluded", "pass", "late reveal is accounted for and bidder A wins", late_entries, records, late_receipt, signed_agreement(late_receipt)))

    corrupt_records = copy.deepcopy(records)
    corrupt_records[b_reveal_hash]["signature"]["value"] = "A" + corrupt_records[b_reveal_hash]["signature"]["value"][1:]
    corrupt_receipt = signed_receipt(entries, corrupt_records)
    vectors.append(make_vector("invalid-signature-rejects-selection", "fail", "bad record signature rejects the selection instead of improving another bidder's rank", entries, corrupt_records, corrupt_receipt, signed_agreement(corrupt_receipt)))

    mismatch_entries = copy.deepcopy(entries)
    mismatch_records = copy.deepcopy(records)
    mismatched_reveal = unsigned(mismatch_records.pop(b_reveal_hash))
    mismatched_reveal["salt"] = b64url(seed("mismatched opening"))
    mismatched_reveal = sign_artifact(mismatched_reveal, "bidder-b", RECORD_DOMAIN)
    mismatched_hash = digest(unsigned(mismatched_reveal))
    for entry in mismatch_entries:
        if entry["recordRef"]["contentHash"] == b_reveal_hash:
            locator = "stor-reveal-" + mismatched_hash[:24]
            entry["recordRef"] = attestation_ref("storage-program", locator, mismatched_hash, CLAIMS["bidder-b"])
            entry["anchorReceipt"]["nativeAddress"] = locator
            entry["anchorReceipt"]["contentHash"] = mismatched_hash
            entry["anchorReceipt"]["transactionRef"]["value"] = "tx-" + mismatched_hash[:20]
            entry["anchorReceipt"]["evidence"]["value"] = "proof-" + mismatched_hash[:20]
    mismatch_records[mismatched_hash] = mismatched_reveal
    mismatch_entries.sort(key=lambda item: (item["orderKey"], item["recordRef"]["contentHash"]))
    mismatch_receipt = signed_receipt(mismatch_entries, mismatch_records)
    vectors.append(make_vector("valid-signed-bidhash-mismatch-excluded", "pass", "valid signed reveal that does not open the authoritative commit is explicitly excluded", mismatch_entries, mismatch_records, mismatch_receipt, signed_agreement(mismatch_receipt)))

    tie_entries, tie_records = base_material(("80", "80", "120"))
    tie_receipt = signed_receipt(tie_entries, tie_records)
    vectors.append(make_vector("equal-price-earliest-commit", "pass", "equal price uses authenticated commit timestamp", tie_entries, tie_records, tie_receipt, signed_agreement(tie_receipt)))

    exact_tie_entries, exact_tie_records = base_material(("80", "80", "120"), equal_commit_time=True)
    exact_tie_receipt = signed_receipt(exact_tie_entries, exact_tie_records)
    vectors.append(make_vector("equal-price-equal-time-bidhash", "pass", "same-time tie uses ascending lowercase bidHash", exact_tie_entries, exact_tie_records, exact_tie_receipt, signed_agreement(exact_tie_receipt)))

    fractional_entries, fractional_records = base_material(("80.05", "80.5", "120"))
    fractional_receipt = signed_receipt(fractional_entries, fractional_records)
    vectors.append(make_vector("fractional-price-full-precision", "pass", "CD-1 decimals compare at full precision without binary floating point", fractional_entries, fractional_records, fractional_receipt, signed_agreement(fractional_receipt)))

    wrong_address_entries = copy.deepcopy(entries)
    for entry in wrong_address_entries:
        record = records[entry["recordRef"]["contentHash"]]
        if record["bidderClaim"] == CLAIMS["bidder-b"] and record["recordKind"] == "reveal":
            entry["anchorReceipt"]["logicalAddress"] = "dacs3:auction:" + JOB_ID + ":wrong"
    wrong_address_receipt = signed_receipt(wrong_address_entries, records)
    vectors.append(make_vector("wrong-address-record-rejects-selection", "fail", "anchor/address contradiction rejects instead of improving another bidder's rank", wrong_address_entries, records, wrong_address_receipt, signed_agreement(wrong_address_receipt)))

    bad_count = copy.deepcopy(receipt)
    bad_count["completenessEvidence"]["recordCount"] = "5"
    bad_count = resign_receipt(bad_count)
    vectors.append(make_vector("record-count-proof-mismatch", "fail", "signed receipt cannot contradict proof-bound exact count", entries, records, bad_count, signed_agreement(bad_count)))

    return {
        "set": "sealed-auction-completeness-v0.6",
        "spec": "DACS-3 §8.4.4 SAC-1..SAC-10",
        "issue": "https://github.com/DACS-Agent-commerce/DACS-Standard/issues/376",
        "decisionModel": "pass only after exact current complete-set, receipt and agreement reproduction; deterministic contradictions fail; unavailable authority is indeterminate",
        "fixtureProfile": {
            "recordSignature": RECORD_DOMAIN + " || sha256(JCS(record without signature))",
            "receiptSignature": RECEIPT_DOMAIN + " || sha256(JCS(receipt without signature))",
            "agreementSignature": AGREEMENT_DOMAIN + " || sha256(JCS(agreement without signatures))",
            "candidateSetProof": "deterministic Ed25519 test binding over prefix/finalized-state/recordSetHash/count; models the SAC-3 adapter boundary, not a production Demos proof",
            "generator": "scripts/generate_sealed_auction_completeness_vectors.py",
        },
        "publicKeys": {name: public_key(name) for name in KEYS},
        "count": len(vectors),
        "hash": vector_hash(vectors),
        "vectors": vectors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if args.write:
        OUTPUT.write_text(rendered, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
        print(f"ERROR: {OUTPUT.relative_to(ROOT)} is stale; run with --write")
        return 1
    print("sealed-auction completeness vectors are deterministic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
