#!/usr/bin/env python3
"""Generate DACS-3 v0.6 sealed-auction completeness vectors."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
from functools import cmp_to_key
from itertools import zip_longest
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
FOREIGN_JOB_ID = "01JYYYYYYYYYYYYYYYYYYYYYYYYY"
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
CD1_AMOUNT = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$")
PRICE_KEYS = frozenset({"amount", "currency", "unit"})
COMMIT_RECORD_KEYS = frozenset({
    "sealedAuctionRecordVersion", "recordKind", "jobId", "listingRef",
    "phaseIndex", "bidderClaim", "bidHash", "createdAt", "signature",
})
REVEAL_RECORD_KEYS = COMMIT_RECORD_KEYS | {"commitRef", "bid", "salt"}


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


def binding_definition(
    *,
    proof_key: str | None = None,
    binding_id: str = "test-complete-log",
    binding_version: str = "1",
    maximum_records: str = "100",
    maximum_bytes: str = "1048576",
) -> dict:
    """Return the authenticated test adapter policy resolved through SR-2.

    This is a portable fixture definition, not a Demos-native binding claim.
    """
    return {
        "candidateSetBindingDefinitionVersion": "1",
        "bindingId": binding_id,
        "bindingVersion": binding_version,
        "substrate": "test-bft",
        "collectionPrefixTemplate": "dacs3:auction:{jobId}",
        "proof": {
            "kind": "test-complete-prefix",
            "domain": BINDING_DOMAIN,
            "verificationKey": proof_key or public_key("binding"),
        },
        "finality": {
            "profile": "test-bft-final",
            "maximumLagStates": "0",
            "minimumTimestampRule": "at-or-after-reveal-deadline",
        },
        "admission": {
            "writerRule": "record-bidder-claim",
            "addressCodec": "dacs3-sealed-auction-v1",
        },
        "limits": {
            "maximumRecords": maximum_records,
            "maximumBytes": maximum_bytes,
        },
        "ordering": "orderKey-then-contentHash-ascending",
        "conflictRule": "indeterminate-on-finalized-conflict",
    }


def binding_definition_ref(definition: dict | None = None) -> dict:
    definition = definition or binding_definition()
    return attestation_ref(
        "storage-program",
        "stor-test-binding-" + digest(definition)[:24],
        digest(definition),
        CLAIMS["publisher"],
    )


def binding_ref(definition: dict | None = None, *, binding_id: str | None = None,
                binding_version: str | None = None) -> dict:
    definition = definition or binding_definition()
    return {
        "bindingId": binding_id or definition["bindingId"],
        "bindingVersion": binding_version or definition["bindingVersion"],
        "definitionRef": binding_definition_ref(definition),
    }


def binding_resolution(definition: dict | None = None, *, reference: dict | None = None,
                       binding_id: str | None = None,
                       binding_version: str | None = None) -> dict:
    definition = definition or binding_definition()
    return {
        "registryId": "dacs-sr2-binding-registry-v1",
        "governanceClaim": CLAIMS["publisher"],
        "authenticated": True,
        "bindingId": binding_id or definition["bindingId"],
        "bindingVersion": binding_version or definition["bindingVersion"],
        "definitionRef": copy.deepcopy(reference or binding_definition_ref(definition)),
        "definition": copy.deepcopy(definition),
    }


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


def decimal_parts(value: object) -> tuple[str, str] | None:
    """Return unsigned CD-1 digits without converting or rewriting signed bytes."""
    if not isinstance(value, str) or not CD1_AMOUNT.fullmatch(value):
        return None
    whole, _, fraction = value.partition(".")
    return whole, fraction


def classify_amount(value: object) -> tuple[str, tuple[str, str] | None]:
    parts = decimal_parts(value)
    if parts is not None:
        return ("non-positive" if value == "0" else "positive"), parts
    if isinstance(value, str) and value.startswith("-"):
        magnitude = decimal_parts(value[1:])
        if magnitude is not None:
            return "non-positive", magnitude
    return "malformed", None


def price_amount(price: object) -> tuple[str, tuple[str, str] | None]:
    if (
        not isinstance(price, dict)
        or not {"amount", "currency"} <= set(price) <= PRICE_KEYS
        or not isinstance(price.get("currency"), str)
        or ("unit" in price and not isinstance(price["unit"], str))
    ):
        return "malformed", None
    return classify_amount(price["amount"])


def compare_decimal_parts(left: tuple[str, str], right: tuple[str, str]) -> int:
    """Compare arbitrary-length canonical non-negative decimals exactly."""
    left_whole, left_fraction = left
    right_whole, right_fraction = right
    if len(left_whole) != len(right_whole):
        return -1 if len(left_whole) < len(right_whole) else 1
    if left_whole != right_whole:
        return -1 if left_whole < right_whole else 1
    for left_digit, right_digit in zip_longest(left_fraction, right_fraction, fillvalue="0"):
        if left_digit != right_digit:
            return -1 if left_digit < right_digit else 1
    return 0


def logical_address(job_id: str, kind: str, bidder_claim: str, value: str) -> str:
    encoded = bidder_claim.replace("%", "%25").replace(":", "%3A")
    return f"dacs3:auction:{job_id}:{kind}:{encoded}:{value}"


def make_record_pair(
    name: str,
    price: object,
    commit_time: int,
    reveal_time: int,
    ordinal: int,
    *,
    job_id: str = JOB_ID,
    listing_ref: dict = LISTING_REF,
    phase_index: int = PHASE_INDEX,
) -> tuple[list[dict], dict]:
    claim = CLAIMS[name]
    bid = {
        "price": copy.deepcopy(price),
        "deliverable": {"deliverableType": "digital", "hash": "ab" * 32},
    }
    salt = seed("salt " + name)
    commitment = bid_hash(bid, salt)
    commit = sign_artifact({
        "sealedAuctionRecordVersion": "1",
        "recordKind": "commit",
        "jobId": job_id,
        "listingRef": listing_ref,
        "phaseIndex": phase_index,
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
        "jobId": job_id,
        "listingRef": listing_ref,
        "phaseIndex": phase_index,
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
                "logicalAddress": logical_address(job_id, record["recordKind"], claim, commitment),
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


def base_material(
    prices: tuple[object, object, object] = ("100", "80", "120"),
    *,
    equal_commit_time: bool = False,
    price_overrides: dict[str, object] | None = None,
    currency: str = "USD",
    job_id: str = JOB_ID,
    listing_ref: dict = LISTING_REF,
    phase_index: int = PHASE_INDEX,
) -> tuple[list[dict], dict]:
    entries: list[dict] = []
    records: dict[str, dict] = {}
    for index, (name, amount) in enumerate(zip(BIDDER_NAMES, prices), start=1):
        commit_time = COMMIT_DEADLINE - (30_000 - index * 2_000)
        if equal_commit_time and name in {"bidder-a", "bidder-b"}:
            commit_time = COMMIT_DEADLINE - 20_000
        pair_entries, pair_records = make_record_pair(
            name,
            (price_overrides or {}).get(name, {"amount": amount, "currency": currency}),
            commit_time,
            COMMIT_DEADLINE + 20_000 + index * 2_000,
            index,
            job_id=job_id,
            listing_ref=listing_ref,
            phase_index=phase_index,
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


def completeness_evidence(
    entries: list[dict],
    collection_prefix: str,
    state: dict = CURRENT_STATE,
    *,
    proof_key_name: str = "binding",
) -> dict:
    evidence = {
        "substrate": "test-bft",
        "finalizedState": copy.deepcopy(state),
        "recordSetHash": digest(entries),
        "recordCount": str(len(entries)),
        "proof": {"kind": "test-complete-prefix", "value": ""},
    }
    proof = KEYS[proof_key_name].sign(
        (BINDING_DOMAIN + digest(binding_payload(collection_prefix, evidence))).encode("ascii")
    )
    evidence["proof"]["value"] = b64url(proof)
    return evidence


def decode_salt(value: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("non-canonical salt encoding")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64url(decoded) != value or len(decoded) < 32:
        raise ValueError("sealed reveal salt must be canonical Base64URL for at least 32 bytes")
    return decoded


def derive(
    entries: list[dict],
    records: dict,
    *,
    selection_rule: str,
    currency: str = "USD",
    reserve: str | None = None,
    job_id: str = JOB_ID,
) -> tuple[list[dict], list[dict], dict | None]:
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
            kind = record.get("recordKind")
            expected_keys = (
                COMMIT_RECORD_KEYS if kind == "commit"
                else REVEAL_RECORD_KEYS if kind == "reveal"
                else frozenset()
            )
            if set(record) != expected_keys:
                reason = "malformed-record"
            signature = record.get("signature", {})
            expected_name = next((name for name, claim in CLAIMS.items() if claim == record.get("bidderClaim")), None)
            if reason is None and (expected_name not in BIDDER_NAMES or signature.get("signer") != record.get("bidderClaim")):
                reason = "bad-signature"
            elif reason is None:
                try:
                    KEYS[expected_name].public_key().verify(
                        base64.urlsafe_b64decode(signature["value"] + "=" * (-len(signature["value"]) % 4)),
                        (RECORD_DOMAIN + digest(unsigned(record))).encode("ascii"),
                    )
                except Exception:
                    reason = "bad-signature"
            if reason is None:
                if kind == "reveal":
                    try:
                        decode_salt(record.get("salt"))
                    except (TypeError, ValueError):
                        reason = "malformed-record"
                    if reason is None:
                        bid = record.get("bid")
                        price = bid.get("price") if isinstance(bid, dict) else None
                        if price_amount(price)[0] == "malformed":
                            reason = "malformed-record"
                want_address = logical_address(
                    job_id, kind or "", record["bidderClaim"], record["bidHash"]
                )
                if reason is None and entry["anchorReceipt"].get("logicalAddress") != want_address:
                    reason = "wrong-address"
                elif reason is None and entry["anchorReceipt"].get("state") != "finalized":
                    reason = "unfinalized"
                elif reason is None:
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
    eligible: list[tuple[dict, dict, dict, dict, tuple[str, str]]] = []
    reserve_parts = decimal_parts(reserve) if reserve is not None else None
    if reserve is not None and (reserve_parts is None or reserve == "0"):
        raise ValueError("fixture reserve must be a positive CD-1 amount")
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
        amount_status, amount = price_amount(price)
        if amount_status == "malformed" or amount is None:
            raise AssertionError("malformed reveal price passed the record gate")
        if price.get("currency") != currency:
            reason = "currency-mismatch"
        elif amount_status == "non-positive":
            reason = "non-positive-price"
        elif reserve_parts is not None:
            reserve_comparison = compare_decimal_parts(amount, reserve_parts)
            if (
                (selection_rule == "lowest-price" and reserve_comparison > 0)
                or (selection_rule == "highest-price" and reserve_comparison < 0)
            ):
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
            eligible.append((commit_entry, commit, reveal_entry, reveal, amount))

    if selection_rule not in {"lowest-price", "highest-price"} or not eligible:
        return record_decisions, bid_decisions, None
    def compare_candidates(left, right):
        price_order = compare_decimal_parts(left[4], right[4])
        if selection_rule == "highest-price":
            price_order = -price_order
        if price_order:
            return price_order
        left_time = left[0]["anchorReceipt"]["blockRef"]["timestamp"]
        right_time = right[0]["anchorReceipt"]["blockRef"]["timestamp"]
        if left_time != right_time:
            return -1 if left_time < right_time else 1
        return (left[1]["bidHash"] > right[1]["bidHash"]) - (
            left[1]["bidHash"] < right[1]["bidHash"]
        )

    eligible.sort(key=cmp_to_key(compare_candidates))
    commit_entry, commit, reveal_entry, reveal, _ = eligible[0]
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


def signed_receipt(
    entries: list[dict],
    records: dict,
    *,
    selection_rule: str = "lowest-price",
    reserve: str | None = None,
    currency: str = "USD",
    state: dict = CURRENT_STATE,
    phase_kind: str = "negotiate-sealed-envelope-procurement-complete",
    job_id: str = JOB_ID,
    listing_ref: dict = LISTING_REF,
    phase_index: int = PHASE_INDEX,
    candidate_binding: dict | None = None,
    proof_key_name: str = "binding",
) -> dict:
    if phase_kind not in {
        "negotiate-sealed-envelope-complete",
        "negotiate-sealed-envelope-procurement-complete",
    }:
        raise ValueError("unsupported complete auction phase")
    collection_prefix = "dacs3:auction:" + job_id
    record_decisions, bid_decisions, winner = derive(
        entries,
        records,
        selection_rule=selection_rule,
        currency=currency,
        reserve=reserve,
        job_id=job_id,
    )
    receipt = {
        "sealedSelectionReceiptVersion": "1",
        "jobId": job_id,
        "listingRef": copy.deepcopy(listing_ref),
        "phaseIndex": phase_index,
        "phaseKind": phase_kind,
        "candidateSetBinding": copy.deepcopy(candidate_binding or binding_ref()),
        "collectionPrefix": collection_prefix,
        "selectionRule": selection_rule,
        "entries": copy.deepcopy(entries),
        "completenessEvidence": completeness_evidence(
            entries,
            collection_prefix,
            state,
            proof_key_name=proof_key_name,
        ),
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
        "jobId": receipt["jobId"],
        "listingRef": copy.deepcopy(receipt["listingRef"]),
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
    if receipt["phaseKind"] == "negotiate-sealed-envelope-complete":
        agreement["parties"][0]["role"] = "seller"
        agreement["parties"][1]["role"] = "buyer"
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
    bidder_claim = next(
        p["primaryClaim"] for p in agreement["parties"]
        if p["role"] in {"buyer", "seller"} and p["primaryClaim"] != CLAIMS["publisher"]
    )
    bidder_name = next(name for name in BIDDER_NAMES if CLAIMS[name] == bidder_claim)
    return sign_artifact(agreement, bidder_name, AGREEMENT_DOMAIN, plural=True)


def selection_receipt_anchor(receipt: dict) -> dict:
    receipt_hash = digest(unsigned(receipt))
    native_address = "stor-selection-" + receipt_hash[:24]
    return {
        "receiptVersion": "1",
        "substrate": "test-bft",
        "finalityProfile": "test-bft-final",
        "logicalAddress": f"dacs3:selection:{receipt['jobId']}:{receipt['phaseIndex']}",
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


def invocation_authority(receipt: dict, *, currency: str = "USD") -> dict:
    return {
        "authenticated": True,
        "jobId": receipt["jobId"],
        "listingRef": copy.deepcopy(receipt["listingRef"]),
        "phaseIndex": receipt["phaseIndex"],
        "phaseKind": receipt["phaseKind"],
        "publisherClaim": CLAIMS["publisher"],
        "selectionRule": receipt["selectionRule"],
        "candidateSetBinding": copy.deepcopy(receipt["candidateSetBinding"]),
        "pricingCurrency": currency,
    }


def replace_record(
    entries: list[dict], records: dict, old_hash: str, replacement: dict
) -> tuple[list[dict], dict]:
    updated_entries = copy.deepcopy(entries)
    updated_records = copy.deepcopy(records)
    updated_records.pop(old_hash)
    replacement_hash = digest(unsigned(replacement))
    updated_records[replacement_hash] = copy.deepcopy(replacement)
    for entry in updated_entries:
        if entry["recordRef"]["contentHash"] != old_hash:
            continue
        locator = "stor-" + replacement["recordKind"] + "-" + replacement_hash[:24]
        entry["recordRef"] = attestation_ref(
            "storage-program", locator, replacement_hash, replacement["bidderClaim"]
        )
        anchor = entry["anchorReceipt"]
        anchor["logicalAddress"] = logical_address(
            replacement["jobId"], replacement["recordKind"],
            replacement["bidderClaim"], replacement["bidHash"],
        )
        anchor["nativeAddress"] = locator
        anchor["contentHash"] = replacement_hash
        anchor["transactionRef"]["value"] = "tx-" + replacement_hash[:20]
        anchor["evidence"]["value"] = "proof-" + replacement_hash[:20]
    updated_entries.sort(
        key=lambda item: (item["orderKey"], item["recordRef"]["contentHash"])
    )
    return updated_entries, updated_records


def make_vector(
    name: str,
    expected: str,
    reason: str,
    entries: list[dict],
    records: dict,
    receipt: dict,
    agreement: dict,
    *,
    reserve: str | None = None,
    reserve_currency: str | None = None,
    currency: str = "USD",
    auction_mode: str | None = None,
    omit_auction_mode: bool = False,
    authenticated_invocation: dict | None = None,
    resolved_binding: dict | None = None,
    **context_overrides,
) -> dict:
    candidate_binding = receipt["candidateSetBinding"]
    definition = binding_definition()
    default_resolution = binding_resolution(
        definition,
        reference=candidate_binding["definitionRef"],
        binding_id=candidate_binding["bindingId"],
        binding_version=candidate_binding["bindingVersion"],
    )
    phase_kind = receipt["phaseKind"]
    effective_mode = auction_mode or (
        "demand" if phase_kind == "negotiate-sealed-envelope-complete"
        else "procurement"
    )
    invocation = authenticated_invocation or invocation_authority(
        receipt, currency=currency
    )
    context = {
        "bindingRegistryAuthority": {
            "registryId": "dacs-sr2-binding-registry-v1",
            "governanceClaim": CLAIMS["publisher"],
        },
        "bindingResolution": copy.deepcopy(
            default_resolution if resolved_binding is None else resolved_binding
        ),
        "authenticatedInvocation": copy.deepcopy(invocation),
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
    listing = {
        "listingRef": copy.deepcopy(receipt["listingRef"]),
        "publisherClaim": CLAIMS["publisher"],
        "phaseIndex": receipt["phaseIndex"],
        "phaseKind": phase_kind,
        "pricingCurrency": currency,
        "parameters": {
            "commitDeadline": COMMIT_DEADLINE,
            "revealWindow": 120,
            "selectionRule": receipt["selectionRule"],
            "candidateSetBinding": receipt["candidateSetBinding"],
            "auctionMode": effective_mode,
        },
    }
    if omit_auction_mode:
        del listing["parameters"]["auctionMode"]
    if reserve is not None:
        listing["pricing"] = {
            "kind": "auction",
            "selectionRule": receipt["selectionRule"],
            "reservePrice": {
                "amount": reserve,
                "currency": reserve_currency or currency,
            },
        }
    return {
        "name": name,
        "expected": expected,
        "reason": reason,
        "listing": listing,
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

    demand_receipt = signed_receipt(
        entries,
        records,
        phase_kind="negotiate-sealed-envelope-complete",
    )
    demand_agreement = signed_agreement(demand_receipt)
    vectors.append(make_vector(
        "complete-demand-absent-auction-mode",
        "pass",
        "demand-complete permits the signed auctionMode discriminator to be absent and assigns winner as buyer",
        entries,
        records,
        demand_receipt,
        demand_agreement,
        omit_auction_mode=True,
    ))
    vectors.append(make_vector(
        "complete-demand-explicit-auction-mode",
        "pass",
        "demand-complete permits explicit demand and assigns winner as buyer",
        entries,
        records,
        demand_receipt,
        demand_agreement,
        auction_mode="demand",
    ))
    vectors.append(make_vector(
        "demand-phase-procurement-mode-rejected",
        "fail",
        "the demand phase cannot be relabelled with procurement auctionMode",
        entries,
        records,
        demand_receipt,
        demand_agreement,
        auction_mode="procurement",
    ))
    vectors.append(make_vector(
        "procurement-phase-demand-mode-rejected",
        "fail",
        "the procurement phase requires the explicit procurement auctionMode",
        entries,
        records,
        receipt,
        agreement,
        auction_mode="demand",
    ))
    wrong_demand_roles = copy.deepcopy(demand_agreement)
    for party in wrong_demand_roles["parties"]:
        party["role"] = (
            "buyer" if party["primaryClaim"] == CLAIMS["publisher"] else "seller"
        )
    wrong_demand_roles = resign_agreement(wrong_demand_roles)
    vectors.append(make_vector(
        "demand-role-direction-rejected",
        "fail",
        "demand-complete rejects procurement party projection even when both parties re-sign",
        entries,
        records,
        demand_receipt,
        wrong_demand_roles,
        auction_mode="demand",
    ))
    no_reserve = make_vector("auction-pricing-without-reserve", "pass", "optional reservePrice may be absent from valid auction pricing", entries, records, receipt, agreement)
    no_reserve["listing"]["pricing"] = {"kind": "auction", "selectionRule": "lowest-price"}
    vectors.append(no_reserve)

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

    deadline_state = {
        "id": "state-reveal-deadline",
        "height": "198",
        "timestamp": REVEAL_DEADLINE,
    }
    deadline_receipt = signed_receipt(entries, records, state=deadline_state)
    vectors.append(make_vector(
        "finalized-state-at-reveal-deadline",
        "pass",
        "a complete authenticated state at the exact reveal deadline satisfies the lower bound",
        entries,
        records,
        deadline_receipt,
        signed_agreement(deadline_receipt),
        latestFinalizedState=copy.deepcopy(deadline_state),
    ))
    before_deadline_state = {
        "id": "state-before-reveal-deadline",
        "height": "197",
        "timestamp": REVEAL_DEADLINE - 1,
    }
    before_deadline_receipt = signed_receipt(
        entries, records, state=before_deadline_state
    )
    vectors.append(make_vector(
        "finalized-state-before-reveal-deadline-rejected",
        "fail",
        "a valid latest-state proof one millisecond before reveal deadline is too early to establish completeness",
        entries,
        records,
        before_deadline_receipt,
        signed_agreement(before_deadline_receipt),
        latestFinalizedState=copy.deepcopy(before_deadline_state),
    ))

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
        entries, records, receipt, agreement, bindingResolution=None,
    ))

    substituted_definition_resolution = binding_resolution()
    substituted_definition_resolution["definition"]["proof"][
        "verificationKey"
    ] = public_key("publisher")
    vectors.append(make_vector(
        "definition-content-hash-substitution-rejected",
        "fail",
        "a substituted resolved definition cannot authenticate under the signed definitionRef content hash",
        entries,
        records,
        receipt,
        agreement,
        resolved_binding=substituted_definition_resolution,
    ))
    substituted_ref_resolution = binding_resolution()
    substituted_ref_resolution["definitionRef"] = binding_definition_ref(
        binding_definition(binding_version="2")
    )
    vectors.append(make_vector(
        "definition-ref-substitution-rejected",
        "fail",
        "a registry result for another immutable definition ref cannot satisfy the signed binding ref",
        entries,
        records,
        receipt,
        agreement,
        resolved_binding=substituted_ref_resolution,
    ))

    alternate_definition = binding_definition(proof_key=public_key("publisher"))
    alternate_binding = binding_ref(alternate_definition)
    alternate_receipt = signed_receipt(
        entries,
        records,
        candidate_binding=alternate_binding,
        proof_key_name="publisher",
    )
    vectors.append(make_vector(
        "self-selected-definition-key-rejected",
        "fail",
        "fully re-signed artifacts cannot replace the authenticated listing's definition reference and proof key",
        entries,
        records,
        alternate_receipt,
        signed_agreement(alternate_receipt),
        authenticated_invocation=invocation_authority(receipt),
        resolved_binding=binding_resolution(alternate_definition),
    ))
    alternate_id_definition = binding_definition(binding_id="self-selected-log")
    alternate_id_binding = binding_ref(alternate_id_definition)
    alternate_id_receipt = signed_receipt(
        entries, records, candidate_binding=alternate_id_binding
    )
    vectors.append(make_vector(
        "binding-id-substitution-rejected",
        "fail",
        "a resolved self-selected binding identity cannot replace the signed invocation binding",
        entries,
        records,
        alternate_id_receipt,
        signed_agreement(alternate_id_receipt),
        authenticated_invocation=invocation_authority(receipt),
        resolved_binding=binding_resolution(alternate_id_definition),
    ))
    alternate_version_definition = binding_definition(binding_version="2")
    alternate_version_binding = binding_ref(alternate_version_definition)
    alternate_version_receipt = signed_receipt(
        entries, records, candidate_binding=alternate_version_binding
    )
    vectors.append(make_vector(
        "binding-version-substitution-rejected",
        "fail",
        "a resolved self-selected binding version cannot replace the signed invocation binding",
        entries,
        records,
        alternate_version_receipt,
        signed_agreement(alternate_version_receipt),
        authenticated_invocation=invocation_authority(receipt),
        resolved_binding=binding_resolution(alternate_version_definition),
    ))
    bounded_definition = binding_definition(maximum_records="5")
    bounded_binding = binding_ref(bounded_definition)
    bounded_receipt = signed_receipt(
        entries, records, candidate_binding=bounded_binding
    )
    vectors.append(make_vector(
        "binding-record-ceiling-exceeded",
        "fail",
        "the authenticated definition's record ceiling rejects rather than truncates a six-record prefix",
        entries,
        records,
        bounded_receipt,
        signed_agreement(bounded_receipt),
        resolved_binding=binding_resolution(bounded_definition),
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

    short_salt_entries = copy.deepcopy(entries)
    short_salt_records = copy.deepcopy(records)
    short_salt_reveal = unsigned(short_salt_records.pop(b_reveal_hash))
    short_salt_reveal["salt"] = "AA"
    short_salt_reveal = sign_artifact(short_salt_reveal, "bidder-b", RECORD_DOMAIN)
    short_salt_hash = digest(unsigned(short_salt_reveal))
    for entry in short_salt_entries:
        if entry["recordRef"]["contentHash"] == b_reveal_hash:
            locator = "stor-reveal-" + short_salt_hash[:24]
            entry["recordRef"] = attestation_ref(
                "storage-program", locator, short_salt_hash, CLAIMS["bidder-b"]
            )
            entry["anchorReceipt"]["nativeAddress"] = locator
            entry["anchorReceipt"]["contentHash"] = short_salt_hash
            entry["anchorReceipt"]["transactionRef"]["value"] = "tx-" + short_salt_hash[:20]
            entry["anchorReceipt"]["evidence"]["value"] = "proof-" + short_salt_hash[:20]
    short_salt_records[short_salt_hash] = short_salt_reveal
    short_salt_entries.sort(
        key=lambda item: (item["orderKey"], item["recordRef"]["contentHash"])
    )
    short_salt_receipt = signed_receipt(short_salt_entries, short_salt_records)
    vectors.append(make_vector(
        "short-salt-reveal-rejects-selection",
        "fail",
        "a fully signed proof-consistent reveal with a decoded salt shorter than 32 bytes rejects the selection instead of improving another bidder's rank",
        short_salt_entries,
        short_salt_records,
        short_salt_receipt,
        signed_agreement(short_salt_receipt),
    ))

    tie_entries, tie_records = base_material(("80", "80", "120"))
    tie_receipt = signed_receipt(tie_entries, tie_records)
    vectors.append(make_vector("equal-price-earliest-commit", "pass", "equal price uses authenticated commit timestamp", tie_entries, tie_records, tie_receipt, signed_agreement(tie_receipt)))

    exact_tie_entries, exact_tie_records = base_material(("80", "80", "120"), equal_commit_time=True)
    exact_tie_receipt = signed_receipt(exact_tie_entries, exact_tie_records)
    vectors.append(make_vector("equal-price-equal-time-bidhash", "pass", "same-time tie uses ascending lowercase bidHash", exact_tie_entries, exact_tie_records, exact_tie_receipt, signed_agreement(exact_tie_receipt)))

    fractional_entries, fractional_records = base_material(("80.05", "80.5", "120"))
    fractional_receipt = signed_receipt(fractional_entries, fractional_records)
    vectors.append(make_vector("fractional-price-full-precision", "pass", "CD-1 decimals compare at full precision without binary floating point", fractional_entries, fractional_records, fractional_receipt, signed_agreement(fractional_receipt)))

    malformed_price_cases = (
        (
            "trailing-linebreak-price-amounts-rejected",
            ("1\n", "1\r", "1\r\n"),
            None,
            "trailing line terminators are not canonical decimals, including JavaScript dollar-anchor edge cases",
        ),
        (
            "nonfinite-price-amounts-rejected",
            ("Infinity", "-Infinity", "NaN"),
            None,
            "non-finite amount spellings make authenticated reveal records malformed",
        ),
        (
            "snan-and-exponent-price-amounts-rejected",
            ("sNaN", "1e3", "1e999999999999999999999999999999999999"),
            None,
            "signaling NaN and ordinary or enormous exponents are not CD-1 amounts",
        ),
        (
            "non-string-price-amounts-rejected",
            (1, None, []),
            None,
            "number, null, and array amounts make authenticated reveal records malformed",
        ),
        (
            "malformed-price-shapes-rejected",
            ("1", "1", "1"),
            {
                "bidder-a": [],
                "bidder-b": {"currency": "USD"},
                "bidder-c": {"amount": "1", "currency": 840},
            },
            "non-object, missing-member, and wrong-typed PriceTerm shapes reject selection",
        ),
        (
            "noncanonical-price-amounts-rejected",
            ("01", "1.0", "+1"),
            None,
            "leading zero, trailing fractional zero, and plus-sign forms are not CD-1",
        ),
        (
            "noncanonical-decimal-shapes-rejected",
            (".1", "1.", " 1"),
            None,
            "missing whole or fractional digits and surrounding whitespace are not CD-1",
        ),
    )
    for name, prices, overrides, reason in malformed_price_cases:
        malformed_entries, malformed_records = base_material(
            prices, price_overrides=overrides
        )
        malformed_receipt = signed_receipt(malformed_entries, malformed_records)
        vectors.append(make_vector(
            name,
            "fail",
            reason,
            malformed_entries,
            malformed_records,
            malformed_receipt,
            signed_agreement(malformed_receipt),
        ))

    eur_entries, eur_records = base_material(currency="EUR")
    eur_receipt = signed_receipt(
        eur_entries, eur_records, currency="EUR", reserve="80"
    )
    vectors.append(make_vector(
        "non-usd-listing-matching-bids",
        "pass",
        "a signed EUR listing derives EUR eligibility and admits the inclusive reserve boundary",
        eur_entries,
        eur_records,
        eur_receipt,
        signed_agreement(eur_receipt),
        currency="EUR",
        reserve="80",
    ))
    mixed_currency_entries, mixed_currency_records = base_material(
        currency="EUR",
        price_overrides={
            "bidder-a": {"amount": "100", "currency": "USD"},
            "bidder-b": {"amount": "80", "currency": "USD"},
        },
    )
    mixed_currency_receipt = signed_receipt(
        mixed_currency_entries, mixed_currency_records, currency="EUR"
    )
    vectors.append(make_vector(
        "non-usd-listing-usd-bids-excluded",
        "pass",
        "USD bids are authenticated and excluded from an EUR listing before EUR winner selection",
        mixed_currency_entries,
        mixed_currency_records,
        mixed_currency_receipt,
        signed_agreement(mixed_currency_receipt),
        currency="EUR",
    ))
    vectors.append(make_vector(
        "non-usd-listing-third-currency-reserve-rejected",
        "fail",
        "a GBP reserve contradicts the signed EUR listing currency",
        eur_entries,
        eur_records,
        eur_receipt,
        signed_agreement(eur_receipt),
        currency="EUR",
        reserve="80",
        reserve_currency="GBP",
    ))

    non_positive_entries, non_positive_records = base_material(("0", "-1", "100"))
    non_positive_receipt = signed_receipt(
        non_positive_entries, non_positive_records, selection_rule="highest-price"
    )
    vectors.append(make_vector(
        "zero-and-negative-prices-excluded",
        "pass",
        "canonical zero and negative amounts are excluded before highest-price selection",
        non_positive_entries,
        non_positive_records,
        non_positive_receipt,
        signed_agreement(non_positive_receipt),
    ))

    long_integer = "12345678901234567890123456789012345678901234567890"
    long_fraction = "0." + "1234567890" * 6
    exact_cases = (
        (
            "long-integer-lowest-price",
            (long_integer + "2", long_integer + "1", long_integer + "3"),
            "lowest-price",
            None,
            "arbitrary-length integers differing beyond decimal context precision select the exact lowest suffix",
        ),
        (
            "long-integer-highest-price",
            (long_integer + "1", long_integer + "2", long_integer + "3"),
            "highest-price",
            None,
            "arbitrary-length integers differing beyond decimal context precision select the exact highest suffix",
        ),
        (
            "long-fraction-lowest-price",
            (long_fraction + "2", long_fraction + "1", long_fraction + "3"),
            "lowest-price",
            None,
            "arbitrary-length fractions differing at the final digit select the exact lowest suffix",
        ),
        (
            "long-fraction-highest-price",
            (long_fraction + "1", long_fraction + "2", long_fraction + "3"),
            "highest-price",
            None,
            "arbitrary-length fractions differing at the final digit select the exact highest suffix",
        ),
        (
            "long-fraction-inclusive-reserve-ceiling",
            (long_fraction + "2", long_fraction + "3", long_fraction + "4"),
            "lowest-price",
            long_fraction + "2",
            "a long price equal to the lowest-price reserve ceiling remains eligible while larger suffixes do not",
        ),
        (
            "long-fraction-inclusive-reserve-floor",
            (long_fraction + "1", long_fraction + "2", "0.1"),
            "highest-price",
            long_fraction + "2",
            "a long price equal to the highest-price reserve floor remains eligible while smaller values do not",
        ),
    )
    for name, prices, rule, reserve, reason in exact_cases:
        exact_entries, exact_records = base_material(prices)
        exact_receipt = signed_receipt(
            exact_entries, exact_records, selection_rule=rule, reserve=reserve
        )
        vectors.append(make_vector(
            name,
            "pass",
            reason,
            exact_entries,
            exact_records,
            exact_receipt,
            signed_agreement(exact_receipt),
            reserve=reserve,
        ))

    foreign_entries, foreign_records = base_material(job_id=FOREIGN_JOB_ID)
    foreign_receipt = signed_receipt(
        foreign_entries, foreign_records, job_id=FOREIGN_JOB_ID
    )
    vectors.append(make_vector(
        "resigned-cross-job-artifacts-rejected",
        "fail",
        "internally consistent foreign-job records, proof, receipt, anchor and agreement cannot replace the authenticated invocation job",
        foreign_entries,
        foreign_records,
        foreign_receipt,
        signed_agreement(foreign_receipt),
        authenticated_invocation=invocation_authority(receipt),
    ))
    foreign_listing_ref = {
        "listingId": "other-complete-sealed-demo",
        "version": 2,
        "contentHash": "92" * 32,
    }
    foreign_listing_entries, foreign_listing_records = base_material(
        listing_ref=foreign_listing_ref
    )
    foreign_listing_receipt = signed_receipt(
        foreign_listing_entries,
        foreign_listing_records,
        listing_ref=foreign_listing_ref,
    )
    vectors.append(make_vector(
        "resigned-cross-listing-artifacts-rejected",
        "fail",
        "internally consistent foreign-listing artifacts cannot replace the authenticated invocation listing",
        foreign_listing_entries,
        foreign_listing_records,
        foreign_listing_receipt,
        signed_agreement(foreign_listing_receipt),
        authenticated_invocation=invocation_authority(receipt),
    ))
    vectors.append(make_vector(
        "resigned-cross-phase-artifacts-rejected",
        "fail",
        "internally consistent demand artifacts cannot replace an authenticated procurement invocation",
        entries,
        records,
        demand_receipt,
        demand_agreement,
        auction_mode="demand",
        authenticated_invocation=invocation_authority(receipt),
    ))

    commit_hash = next(
        record_hash for record_hash, record in records.items()
        if record["recordKind"] == "commit"
        and record["bidderClaim"] == CLAIMS["bidder-a"]
    )
    reveal_hash = next(
        record_hash for record_hash, record in records.items()
        if record["recordKind"] == "reveal"
        and record["bidderClaim"] == CLAIMS["bidder-b"]
    )
    shape_cases = (
        ("signed-commit-extra-member-rejected", commit_hash, "extra", "bidder-a"),
        ("signed-commit-missing-member-rejected", commit_hash, "missing", "bidder-a"),
        ("signed-reveal-extra-member-rejected", reveal_hash, "extra", "bidder-b"),
        ("signed-reveal-missing-member-rejected", reveal_hash, "missing", "bidder-b"),
    )
    for name, old_hash, mutation, signer in shape_cases:
        changed_record = unsigned(records[old_hash])
        if mutation == "extra":
            changed_record["unknownMember"] = "signed-but-forbidden"
        else:
            del changed_record["createdAt"]
        changed_record = sign_artifact(changed_record, signer, RECORD_DOMAIN)
        changed_entries, changed_records = replace_record(
            entries, records, old_hash, changed_record
        )
        changed_receipt = signed_receipt(changed_entries, changed_records)
        vectors.append(make_vector(
            name,
            "fail",
            "an authenticated record with a signed " + mutation + " member violates its exact closed recordKind shape",
            changed_entries,
            changed_records,
            changed_receipt,
            signed_agreement(changed_receipt),
        ))

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
            "candidateSetProof": "authenticated test SR-2 registry resolution pins definition ref/id/version and derives deterministic Ed25519 proof verification, finality, admission, ordering, conflict and resource policy; models the SAC-3 adapter boundary, not a production Demos proof",
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
