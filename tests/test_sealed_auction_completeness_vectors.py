import base64
import copy
import hashlib
import json
import re
import subprocess
import sys
import unittest
from functools import cmp_to_key
from itertools import zip_longest
from pathlib import Path
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from scripts.jcs import canonicalize as jcs_canonicalize


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance/vectors/security/sealed-auction-completeness-v0.6.json"
GENERATOR = ROOT / "scripts/generate_sealed_auction_completeness_vectors.py"
JS_EVALUATOR = ROOT / "scripts/evaluate_sealed_auction_fixture.mjs"
SPEC = ROOT / "spec/DACS-3-NEGOTIATE.md"
MAPPING = ROOT / "spec/DEMOS-MAPPING.md"
RECORD_DOMAIN = "dacs-sealed-auction-record:v1:"
RECEIPT_DOMAIN = "dacs-sealed-selection-receipt:v1:"
AGREEMENT_DOMAIN = "dacs-sealed-selection-agreement:v1:"
BINDING_DOMAIN = "test-candidate-set-proof:v1:"
CONTEXT_BID_DOMAIN = "dacs-sealed-bid-context:v1:"
HISTORICAL_BID_DOMAIN = "dacs-sealed-bid:v1:"
UNSIGNED_CD1 = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")
COMMIT_RECORD_KEYS = {
    "sealedAuctionRecordVersion", "recordKind", "jobId", "listingRef",
    "phaseIndex", "bidderClaim", "channelId", "bidHash", "createdAt", "signature",
}
REVEAL_RECORD_KEYS = COMMIT_RECORD_KEYS | {"commitRef", "bid", "salt"}
BINDING_DEFINITION_KEYS = {
    "candidateSetBindingDefinitionVersion", "bindingId", "bindingVersion",
    "substrate", "collectionPrefixTemplate", "proof", "finality",
    "admission", "limits", "ordering", "conflictRule",
}


def canonical(value):
    return jcs_canonicalize(value).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def unsigned(value):
    return {key: item for key, item in value.items() if key not in {"signature", "signatures"}}


def decode_b64url(value):
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("non-canonical base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("non-canonical base64url")
    return raw


def verify(public_key, signature, payload):
    try:
        Ed25519PublicKey.from_public_bytes(decode_b64url(public_key)).verify(
            decode_b64url(signature), payload
        )
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def bid_hash(bid, salt_text, record=None):
    salt = decode_b64url(salt_text)
    if record is None:
        raise ValueError("complete-profile bidHash requires the carrying record context")
    context = {
        "jobId": record["jobId"],
        "listingRef": record["listingRef"],
        "phaseIndex": record["phaseIndex"],
        "bidderClaim": record["bidderClaim"],
        "channelId": record["channelId"],
        "bid": bid,
    }
    return hashlib.sha256(
        CONTEXT_BID_DOMAIN.encode() + hashlib.sha256(canonical(context)).digest() + salt
    ).hexdigest()


def historical_bid_hash(bid, salt_text):
    salt = decode_b64url(salt_text)
    return hashlib.sha256(
        HISTORICAL_BID_DOMAIN.encode() + hashlib.sha256(canonical(bid)).digest() + salt
    ).hexdigest()


def logical_address(job_id, kind, bidder_claim, value):
    encoded = bidder_claim.replace("%", "%25").replace(":", "%3A")
    return f"dacs3:auction:{job_id}:{kind}:{encoded}:{value}"


def binding_payload(receipt):
    evidence = receipt["completenessEvidence"]
    return {
        "collectionPrefix": receipt["collectionPrefix"],
        "finalizedState": evidence["finalizedState"],
        "recordSetHash": evidence["recordSetHash"],
        "recordCount": evidence["recordCount"],
    }


def compare_ref(left, right):
    return left == right


def inspect_amount(value):
    if isinstance(value, str) and UNSIGNED_CD1.fullmatch(value):
        whole, _, fraction = value.partition(".")
        return ("non-positive" if value == "0" else "positive"), (whole, fraction)
    if (
        isinstance(value, str)
        and value.startswith("-")
        and UNSIGNED_CD1.fullmatch(value[1:])
    ):
        whole, _, fraction = value[1:].partition(".")
        return "non-positive", (whole, fraction)
    return "malformed", None


def inspect_price(price):
    if not isinstance(price, dict):
        return "malformed", None
    keys = set(price)
    if not {"amount", "currency"} <= keys <= {"amount", "currency", "unit"}:
        return "malformed", None
    if not isinstance(price["currency"], str):
        return "malformed", None
    if "unit" in price and not isinstance(price["unit"], str):
        return "malformed", None
    return inspect_amount(price["amount"])


def record_shape_valid(record):
    if not isinstance(record, dict):
        return False
    kind = record.get("recordKind")
    expected_keys = (
        COMMIT_RECORD_KEYS if kind == "commit"
        else REVEAL_RECORD_KEYS if kind == "reveal"
        else set()
    )
    signature = record.get("signature")
    return (
        set(record) == expected_keys
        and record.get("sealedAuctionRecordVersion") == "1"
        and isinstance(signature, dict)
        and set(signature) == {"algorithm", "signer", "value"}
        and signature.get("algorithm") == "ed25519"
        and isinstance(signature.get("signer"), str)
        and isinstance(signature.get("value"), str)
    )


def compare_amounts(left, right):
    left_whole, left_fraction = left
    right_whole, right_fraction = right
    if len(left_whole) != len(right_whole):
        return -1 if len(left_whole) < len(right_whole) else 1
    if left_whole != right_whole:
        return -1 if left_whole < right_whole else 1
    for left_digit, right_digit in zip_longest(
        left_fraction, right_fraction, fillvalue="0"
    ):
        if left_digit != right_digit:
            return -1 if left_digit < right_digit else 1
    return 0


def fixture_record_receipt_matches(receipt, ref, bidder, definition=None):
    """Interpret a receipt already authenticated by the complete-set proof.

    This test-bft binding is a fixture codec, not a native SR-2 verifier.
    """
    definition = definition or {
        "substrate": "test-bft",
        "finality": {"profile": "test-bft-final"},
    }
    required = {
        "receiptVersion", "substrate", "finalityProfile", "logicalAddress",
        "nativeAddress", "contentHash", "transactionRef", "writer", "nonce",
        "state", "observationDisposition", "observedAt", "blockRef", "evidence",
    }
    if not isinstance(receipt, dict) or set(receipt) != required:
        return False
    transaction = receipt["transactionRef"]
    block = receipt["blockRef"]
    evidence = receipt["evidence"]
    admission = definition.get("admission", {})
    writer_bindings = admission.get("writerBindings", {})
    return (
        receipt["receiptVersion"] == "1"
        and receipt["substrate"] == definition["substrate"]
        and receipt["finalityProfile"] == definition["finality"]["profile"]
        and admission.get("writerRule") == "test-native-writer-map-v1"
        and receipt["writer"] == writer_bindings.get(bidder)
        and ("signer" not in ref or ref["signer"] == bidder)
        and isinstance(transaction, dict) and set(transaction) == {"kind", "value"}
        and transaction["kind"] == "test-tx"
        and isinstance(transaction["value"], str) and bool(transaction["value"])
        and isinstance(receipt["nonce"], str)
        and re.fullmatch(r"0|[1-9][0-9]*", receipt["nonce"]) is not None
        and isinstance(block, dict) and set(block) == {"id", "height", "timestamp"}
        and isinstance(block["id"], str) and bool(block["id"])
        and isinstance(block["height"], str)
        and re.fullmatch(r"0|[1-9][0-9]*", block["height"]) is not None
        and type(block["timestamp"]) is int and block["timestamp"] >= 0
        and type(receipt["observedAt"]) is int and receipt["observedAt"] >= 0
        and isinstance(evidence, dict) and set(evidence) == {"kind", "value"}
        and evidence["kind"] == "test-finality"
        and isinstance(evidence["value"], str) and bool(evidence["value"])
    )


class Evaluator:
    def __init__(self, vector):
        self.vector = vector
        self.listing = vector["listing"]
        self.receipt = vector["receipt"]
        self.agreement = vector["agreement"]
        self.ctx = vector["context"]

    def evaluate(self):
        structural = self._structural_gate()
        if structural:
            return structural
        completeness = self._complete_set_gate()
        if completeness:
            return completeness
        derived = self._derive_decisions()
        if isinstance(derived, str):
            return derived
        record_decisions, bid_decisions, winner = derived
        receipt_gate = self._receipt_gate(record_decisions, bid_decisions, winner)
        if receipt_gate:
            return receipt_gate
        return self._agreement_gate(winner)

    def _structural_gate(self):
        params = self.listing.get("parameters", {})
        rule = params.get("selectionRule")
        phase_kind = self.listing.get("phaseKind")
        if phase_kind not in {
            "negotiate-sealed-envelope-complete",
            "negotiate-sealed-envelope-procurement-complete",
        }:
            return "fail"
        mode_present = "auctionMode" in params
        mode = params.get("auctionMode")
        if (
            phase_kind == "negotiate-sealed-envelope-complete"
            and mode_present and mode != "demand"
        ) or (
            phase_kind == "negotiate-sealed-envelope-procurement-complete"
            and (not mode_present or mode != "procurement")
        ):
            return "fail"
        if rule not in {"lowest-price", "highest-price"}:
            return "fail"
        if self.receipt.get("selectionRule") != rule:
            return "fail"
        candidate_binding = params.get("candidateSetBinding")
        if (
            not isinstance(candidate_binding, dict)
            or set(candidate_binding) != {"bindingId", "bindingVersion", "definitionRef"}
            or self.receipt.get("candidateSetBinding") != candidate_binding
        ):
            return "fail"
        definition_ref = candidate_binding.get("definitionRef")
        if (
            not isinstance(definition_ref, dict)
            or set(definition_ref) != {"anchor", "contentHash", "signer"}
            or not isinstance(definition_ref.get("anchor"), dict)
            or set(definition_ref["anchor"]) != {"kind", "locator"}
        ):
            return "fail"

        invocation = self.ctx.get("authenticatedInvocation")
        if invocation is None:
            return "indeterminate"
        invocation_keys = {
            "authenticated", "jobId", "listingRef", "phaseIndex", "phaseKind",
            "publisherClaim", "selectionRule", "candidateSetBinding",
            "pricingCurrency",
        }
        if (
            not isinstance(invocation, dict)
            or set(invocation) != invocation_keys
            or invocation.get("authenticated") is not True
        ):
            return "fail"
        for actual, expected in (
            (self.listing.get("listingRef"), invocation["listingRef"]),
            (self.listing.get("phaseIndex"), invocation["phaseIndex"]),
            (phase_kind, invocation["phaseKind"]),
            (self.listing.get("publisherClaim"), invocation["publisherClaim"]),
            (rule, invocation["selectionRule"]),
            (candidate_binding, invocation["candidateSetBinding"]),
            (self.listing.get("pricingCurrency"), invocation["pricingCurrency"]),
        ):
            if actual != expected:
                return "fail"
        listing_currency = invocation.get("pricingCurrency")
        if not isinstance(listing_currency, str) or not listing_currency:
            return "fail"
        self.listing_currency = listing_currency

        authority = self.ctx.get("bindingRegistryAuthority")
        if authority is None:
            return "indeterminate"
        if (
            not isinstance(authority, dict)
            or set(authority) != {"registryId", "governanceClaim"}
        ):
            return "fail"
        resolution = self.ctx.get("bindingResolution")
        if resolution is None:
            return "indeterminate"
        resolution_keys = {
            "registryId", "governanceClaim", "authenticated", "bindingId",
            "bindingVersion", "definitionRef", "definition",
        }
        if (
            not isinstance(resolution, dict)
            or set(resolution) != resolution_keys
            or resolution.get("authenticated") is not True
            or resolution.get("registryId") != authority.get("registryId")
            or resolution.get("governanceClaim") != authority.get("governanceClaim")
            or resolution.get("bindingId") != candidate_binding.get("bindingId")
            or resolution.get("bindingVersion") != candidate_binding.get("bindingVersion")
            or not isinstance(candidate_binding.get("bindingVersion"), str)
            or re.fullmatch(r"[1-9][0-9]*", candidate_binding.get("bindingVersion", "")) is None
            or resolution.get("definitionRef") != definition_ref
            or definition_ref.get("signer") != authority.get("governanceClaim")
        ):
            return "fail"
        definition = resolution.get("definition")
        if (
            not isinstance(definition, dict)
            or set(definition) != BINDING_DEFINITION_KEYS
            or digest(definition) != definition_ref.get("contentHash")
            or definition.get("bindingId") != candidate_binding.get("bindingId")
            or definition.get("bindingVersion") != candidate_binding.get("bindingVersion")
            or definition.get("candidateSetBindingDefinitionVersion") != "1"
            or definition.get("collectionPrefixTemplate") != "dacs3:auction:{jobId}"
            or definition.get("ordering") != "orderKey-then-contentHash-ascending"
            or definition.get("conflictRule") != "indeterminate-on-finalized-conflict"
            or not isinstance(definition.get("proof"), dict)
            or set(definition["proof"]) != {"kind", "domain", "verificationKey"}
            or not isinstance(definition.get("finality"), dict)
            or set(definition["finality"]) != {
                "profile", "maximumLagStates", "minimumTimestampRule"
            }
            or definition["finality"].get("maximumLagStates") != "0"
            or definition["finality"].get("minimumTimestampRule")
            != "at-or-after-reveal-deadline"
            or not isinstance(definition.get("admission"), dict)
            or set(definition["admission"])
            != {"writerRule", "writerBindings", "addressCodec"}
            or definition["admission"].get("writerRule")
            != "test-native-writer-map-v1"
            or definition["admission"].get("addressCodec")
            != "dacs3-sealed-auction-v1"
            or not isinstance(definition["admission"].get("writerBindings"), dict)
            or not definition["admission"]["writerBindings"]
            or any(
                not isinstance(claim, str)
                or not isinstance(writer, str)
                or not writer
                for claim, writer in definition["admission"]["writerBindings"].items()
            )
            or not isinstance(definition.get("limits"), dict)
            or set(definition["limits"]) != {"maximumRecords", "maximumBytes"}
        ):
            return "fail"
        try:
            if (
                int(definition["limits"]["maximumRecords"]) <= 0
                or str(int(definition["limits"]["maximumRecords"]))
                != definition["limits"]["maximumRecords"]
                or int(definition["limits"]["maximumBytes"]) <= 0
                or str(int(definition["limits"]["maximumBytes"]))
                != definition["limits"]["maximumBytes"]
            ):
                return "fail"
        except (TypeError, ValueError):
            return "fail"
        self.binding_definition = definition
        if self.receipt.get("sealedSelectionReceiptVersion") != "1":
            return "fail"
        job_id = invocation.get("jobId")
        if not isinstance(job_id, str) or self.receipt.get("collectionPrefix") != (
            "dacs3:auction:" + quote(job_id, safe="")
        ):
            return "fail"
        pricing = self.listing.get("pricing")
        if "pricing" in self.listing:
            if (
                not isinstance(pricing, dict)
                or pricing.get("kind") != "auction"
                or pricing.get("selectionRule") != rule
            ):
                return "fail"
            if "reservePrice" in pricing:
                reserve = pricing["reservePrice"]
                reserve_status, _ = inspect_price(reserve)
                if reserve_status != "positive" or reserve.get("currency") != listing_currency:
                    return "fail"
        for key, expected in (
            ("jobId", job_id),
            ("listingRef", invocation["listingRef"]),
            ("phaseIndex", invocation["phaseIndex"]),
            ("phaseKind", invocation["phaseKind"]),
        ):
            if self.receipt.get(key) != expected:
                return "fail"
        return None

    def _complete_set_gate(self):
        entries = self.receipt.get("entries")
        evidence = self.receipt.get("completenessEvidence")
        if not isinstance(entries, list) or not isinstance(evidence, dict):
            return "fail"
        if entries != sorted(entries, key=lambda item: (item.get("orderKey", ""), item.get("recordRef", {}).get("contentHash", ""))):
            return "fail"
        if len({item.get("recordRef", {}).get("contentHash") for item in entries}) != len(entries):
            return "fail"
        if evidence.get("recordSetHash") != digest(entries):
            return "fail"
        if evidence.get("recordCount") != str(len(entries)):
            return "fail"
        limits = self.binding_definition["limits"]
        if (
            len(entries) > int(limits["maximumRecords"])
            or len(canonical(entries)) > int(limits["maximumBytes"])
        ):
            return "fail"
        if evidence.get("substrate") != self.binding_definition.get("substrate"):
            return "fail"
        conflicts = self.ctx.get("knownConflictingStates")
        if not isinstance(conflicts, list) or conflicts:
            return "indeterminate"
        if evidence.get("finalizedState") != self.ctx.get("latestFinalizedState"):
            return "indeterminate"
        finalized_state = evidence.get("finalizedState")
        reveal_deadline = (
            self.listing["parameters"]["commitDeadline"]
            + self.listing["parameters"]["revealWindow"] * 1000
        )
        if (
            not isinstance(finalized_state, dict)
            or type(finalized_state.get("timestamp")) is not int
            or finalized_state["timestamp"] < reveal_deadline
        ):
            return "fail"
        proof = evidence.get("proof")
        proof_policy = self.binding_definition["proof"]
        if not isinstance(proof, dict) or not proof.get("value"):
            return "indeterminate"
        if proof.get("kind") != proof_policy.get("kind"):
            return "fail"
        public_key = proof_policy.get("verificationKey")
        if not public_key:
            return "indeterminate"
        payload = (
            proof_policy.get("domain", "") + digest(binding_payload(self.receipt))
        ).encode("ascii")
        if not verify(public_key, proof.get("value"), payload):
            return "fail"
        return None

    def _derive_decisions(self):
        entries = self.receipt["entries"]
        records = self.ctx.get("resolvedRecords", {})
        public_keys = self.ctx.get("recordPublicKeys", {})
        channel_assignments = self.ctx.get("authenticatedChannelAssignments")
        if channel_assignments is None:
            return "indeterminate"
        if not isinstance(channel_assignments, dict):
            return "fail"
        commit_deadline = self.listing["parameters"]["commitDeadline"]
        reveal_deadline = commit_deadline + self.listing["parameters"]["revealWindow"] * 1000
        record_decisions = []
        commits = {}
        reveals = {}

        for entry in entries:
            ref = entry.get("recordRef", {})
            record_hash = ref.get("contentHash")
            record = records.get(record_hash)
            if record is None:
                return "indeterminate"
            reason = None
            disposition = None
            kind = record.get("recordKind") if isinstance(record, dict) else None
            if not record_shape_valid(record):
                reason = "malformed-record"
            elif digest(unsigned(record)) != record_hash:
                reason = "malformed-record"
            elif record["jobId"] != self.receipt["jobId"] or record["listingRef"] != self.receipt["listingRef"] or record["phaseIndex"] != self.receipt["phaseIndex"]:
                reason = "wrong-session"
            else:
                signature = record.get("signature", {})
                key = public_keys.get(record.get("bidderClaim"))
                if key is None:
                    return "indeterminate"
                if signature.get("signer") != record.get("bidderClaim") or signature.get("algorithm") != "ed25519" or not verify(
                    key,
                    signature.get("value"),
                    (RECORD_DOMAIN + record_hash).encode("ascii"),
                ):
                    reason = "bad-signature"
                else:
                    assignment = channel_assignments.get(record["bidderClaim"])
                    if assignment is None:
                        return "indeterminate"
                    expected_members = sorted((
                        self.listing["publisherClaim"], record["bidderClaim"]
                    ))
                    if (
                        not isinstance(assignment, dict)
                        or set(assignment) != {"authenticated", "channelId", "members"}
                        or assignment.get("authenticated") is not True
                        or assignment.get("channelId") != record.get("channelId")
                        or assignment.get("members") != expected_members
                    ):
                        reason = "wrong-channel"
                    if kind == "reveal":
                        try:
                            if len(decode_b64url(record["salt"])) < 32:
                                reason = "malformed-record"
                        except (KeyError, TypeError, ValueError):
                            reason = "malformed-record"
                        if reason is None:
                            bid = record.get("bid")
                            price = bid.get("price") if isinstance(bid, dict) else None
                            if inspect_price(price)[0] == "malformed":
                                reason = "malformed-record"
                    if reason is None:
                        receipt = entry.get("anchorReceipt", {})
                        expected_address = logical_address(record["jobId"], kind, record["bidderClaim"], record["bidHash"])
                        if receipt.get("logicalAddress") != expected_address or receipt.get("contentHash") != record_hash or receipt.get("nativeAddress") != ref.get("anchor", {}).get("locator"):
                            reason = "wrong-address"
                        elif not fixture_record_receipt_matches(
                            receipt,
                            ref,
                            record["bidderClaim"],
                            self.binding_definition,
                        ):
                            reason = "wrong-address"
                        elif receipt.get("state") != "finalized" or receipt.get("observationDisposition") != "established" or not isinstance(receipt.get("blockRef", {}).get("timestamp"), int):
                            reason = "unfinalized"
                        else:
                            timestamp = receipt["blockRef"]["timestamp"]
                            if kind == "commit" and timestamp > commit_deadline:
                                reason = "late-commit"
                            elif kind == "reveal" and timestamp > reveal_deadline:
                                reason = "late-reveal"
                            elif kind == "reveal" and timestamp < commit_deadline:
                                reason = "early-reveal"
                            else:
                                disposition = "admitted-commit" if kind == "commit" else "admitted-reveal"
                                (commits if kind == "commit" else reveals).setdefault(record["bidderClaim"], []).append((entry, record))
            record_decisions.append({
                "recordContentHash": record_hash,
                "disposition": disposition or "excluded",
                **({"reason": reason} if reason else {}),
            })
            if reason in {"malformed-record", "wrong-session", "bad-signature", "wrong-address", "wrong-channel", "unfinalized"}:
                return "fail"

        bidders = sorted({record.get("bidderClaim") for record in records.values() if isinstance(record, dict) and record.get("bidderClaim")})
        bid_decisions = []
        eligible = []
        reserve = self.listing.get("pricing", {}).get("reservePrice")
        reserve_amount = inspect_price(reserve)[1] if reserve is not None else None
        decision_index = {
            decision["recordContentHash"]: index
            for index, decision in enumerate(record_decisions)
        }
        for bidder in bidders:
            candidate_commits = commits.get(bidder, [])
            if not candidate_commits:
                bid_decisions.append({"bidderClaim": bidder, "disposition": "excluded", "reason": "no-authoritative-commit"})
                continue
            candidate_commits.sort(key=lambda pair: (pair[0]["anchorReceipt"]["blockRef"]["timestamp"], pair[1]["bidHash"]))
            commit_entry, commit = candidate_commits[0]
            for later_entry, _ in candidate_commits[1:]:
                content_hash = later_entry["recordRef"]["contentHash"]
                record_decisions[decision_index[content_hash]] = {
                    "recordContentHash": content_hash,
                    "disposition": "excluded",
                    "reason": "non-authoritative-commit",
                }
            commit_ref = commit_entry["recordRef"]
            bidder_reveals = sorted(
                reveals.get(bidder, []),
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
                    opens = bid_hash(reveal["bid"], reveal["salt"], reveal)
                except (KeyError, TypeError, ValueError):
                    continue
                if (
                    compare_ref(reveal.get("commitRef"), commit_ref)
                    and reveal.get("channelId") == commit.get("channelId")
                    and reveal.get("bidHash") == commit["bidHash"] == opens
                ):
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
            amount_status, amount = inspect_price(price)
            if amount_status == "malformed" or amount is None:
                raise AssertionError("malformed reveal price passed the record gate")
            if price.get("currency") != self.listing_currency:
                reason = "currency-mismatch"
            elif amount_status == "non-positive":
                reason = "non-positive-price"
            elif reserve_amount is not None:
                reserve_order = compare_amounts(amount, reserve_amount)
                if (
                    self.receipt["selectionRule"] == "lowest-price"
                    and reserve_order > 0
                ) or (
                    self.receipt["selectionRule"] == "highest-price"
                    and reserve_order < 0
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

        if not eligible:
            return record_decisions, bid_decisions, None
        def compare_candidates(left, right):
            order = compare_amounts(left[4], right[4])
            if self.receipt["selectionRule"] == "highest-price":
                order = -order
            if order:
                return order
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

    def _receipt_gate(self, record_decisions, bid_decisions, winner):
        if self.receipt.get("recordDecisions") != record_decisions:
            return "fail"
        if self.receipt.get("bidDecisions") != bid_decisions:
            return "fail"
        if self.receipt.get("winner") != winner:
            return "fail"
        key = self.ctx.get("orchestratorPublicKey")
        if key is None:
            return "indeterminate"
        signature = self.receipt.get("signature", {})
        if signature.get("signer") != self.ctx.get("expectedOrchestratorClaim") or signature.get("algorithm") != "ed25519":
            return "fail"
        receipt_hash = digest(unsigned(self.receipt))
        if not verify(key, signature.get("value"), (RECEIPT_DOMAIN + receipt_hash).encode("ascii")):
            return "fail"
        anchor = self.ctx.get("selectionReceiptAnchor")
        if anchor is None:
            return "indeterminate"
        expected_hash = receipt_hash
        expected_logical = f"dacs3:selection:{self.receipt['jobId']}:{self.receipt['phaseIndex']}"
        expected_native = "stor-selection-" + expected_hash[:24]
        if (
            anchor.get("logicalAddress") != expected_logical
            or anchor.get("nativeAddress") != expected_native
            or anchor.get("contentHash") != expected_hash
            or anchor.get("writer") != signature.get("signer")
            or anchor.get("state") != "finalized"
            or anchor.get("observationDisposition") != "established"
            or not isinstance(anchor.get("blockRef", {}).get("timestamp"), int)
        ):
            return "fail"
        return None

    def _agreement_gate(self, winner):
        agreement = self.agreement
        if winner is None:
            return "fail"
        if agreement.get("sealedSelectionAgreementVersion") != "1" or any(
            key in agreement for key in (
                "agreementVersion", "payeeBoundAgreementVersion",
                "identityBoundAgreementVersion", "identityBoundPayeeAgreementVersion",
            )
        ):
            return "fail"
        receipt_hash = digest(unsigned(self.receipt))
        ref = agreement.get("selectionReceiptRef", {})
        if ref.get("contentHash") != receipt_hash:
            return "fail"
        receipt_anchor = self.ctx.get("selectionReceiptAnchor")
        if receipt_anchor is None:
            return "indeterminate"
        if ref.get("anchor", {}).get("locator") != receipt_anchor.get("nativeAddress"):
            return "fail"
        if agreement.get("jobId") != self.receipt.get("jobId") or agreement.get("listingRef") != self.receipt.get("listingRef"):
            return "fail"
        if agreement.get("terms", {}).get("price") != winner.get("price"):
            return "fail"
        buyers = [p for p in agreement.get("parties", []) if p.get("role") == "buyer"]
        sellers = [p for p in agreement.get("parties", []) if p.get("role") == "seller"]
        if len(buyers) != 1 or len(sellers) != 1:
            return "fail"
        publisher = self.listing.get("publisherClaim")
        selected_bidder = winner.get("bidderClaim")
        if self.listing.get("phaseKind") == "negotiate-sealed-envelope-complete":
            expected_buyer, expected_seller = selected_bidder, publisher
        else:
            expected_buyer, expected_seller = publisher, selected_bidder
        if (
            buyers[0].get("primaryClaim") != expected_buyer
            or sellers[0].get("primaryClaim") != expected_seller
        ):
            return "fail"
        agreement_hash = digest(unsigned(agreement))
        signatures = agreement.get("signatures", [])
        required = {buyers[0]["primaryClaim"], sellers[0]["primaryClaim"]}
        if {signature.get("party") for signature in signatures} != required:
            return "fail"
        for signature in signatures:
            key = self.ctx.get("partyPublicKeys", {}).get(signature.get("party"))
            if key is None:
                return "indeterminate"
            if signature.get("algorithm") != "ed25519" or not verify(
                key,
                signature.get("value"),
                (AGREEMENT_DOMAIN + agreement_hash).encode("ascii"),
            ):
                return "fail"
        return "pass"


class SealedAuctionCompletenessVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_count_hash_and_unique_names(self):
        vectors = self.data["vectors"]
        raw = json.dumps(vectors, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(self.data["hash"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(len(vectors), len({vector["name"] for vector in vectors}))

    def test_generator_is_deterministic(self):
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_javascript_runtime_reproduces_exact_roots_and_winners(self):
        result = subprocess.run(
            ["node", str(JS_EVALUATOR), str(VECTORS)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        actual = {item["name"]: item for item in json.loads(result.stdout)}
        controls = {
            "auction-pricing-without-reserve",
            "trailing-linebreak-price-amounts-rejected",
            "complete-lowest-price",
            "complete-demand-absent-auction-mode",
            "complete-demand-explicit-auction-mode",
            "demand-phase-procurement-mode-rejected",
            "procurement-phase-demand-mode-rejected",
            "demand-role-direction-rejected",
            "complete-highest-price",
            "finalized-state-at-reveal-deadline",
            "finalized-state-before-reveal-deadline-rejected",
            "binding-definition-unavailable",
            "definition-content-hash-substitution-rejected",
            "definition-ref-substitution-rejected",
            "self-selected-definition-key-rejected",
            "binding-id-substitution-rejected",
            "binding-version-substitution-rejected",
            "noncanonical-binding-version-rejected",
            "binding-record-ceiling-exceeded",
            "equal-price-earliest-commit",
            "equal-price-equal-time-bidhash",
            "fractional-price-full-precision",
            "nonfinite-price-amounts-rejected",
            "snan-and-exponent-price-amounts-rejected",
            "non-string-price-amounts-rejected",
            "malformed-price-shapes-rejected",
            "noncanonical-price-amounts-rejected",
            "noncanonical-decimal-shapes-rejected",
            "non-usd-listing-matching-bids",
            "non-usd-listing-usd-bids-excluded",
            "non-usd-listing-third-currency-reserve-rejected",
            "zero-and-negative-prices-excluded",
            "long-integer-lowest-price",
            "long-integer-highest-price",
            "long-fraction-lowest-price",
            "long-fraction-highest-price",
            "long-fraction-inclusive-reserve-ceiling",
            "long-fraction-inclusive-reserve-floor",
            "resigned-cross-job-artifacts-rejected",
            "resigned-cross-listing-artifacts-rejected",
            "resigned-cross-phase-artifacts-rejected",
            "signed-commit-extra-member-rejected",
            "signed-commit-missing-member-rejected",
            "signed-reveal-extra-member-rejected",
            "signed-reveal-missing-member-rejected",
            "signed-commit-wrong-version-rejected",
            "signed-reveal-wrong-version-rejected",
            "signed-commit-signature-extra-member-rejected",
            "signed-reveal-signature-extra-member-rejected",
            "copied-commitment-as-other-bidder-excluded",
            "cross-channel-commitment-replay-excluded",
            "cross-job-commitment-replay-excluded",
            "cross-listing-commitment-replay-excluded",
            "cross-phase-commitment-replay-excluded",
            "historical-v1-commitment-in-complete-profile-excluded",
            "other-bidder-channel-assignment-rejected",
            "channel-assignment-unavailable",
            "premature-reveal-before-commit-deadline-excluded",
            "reveal-at-commit-deadline-admitted",
        }
        self.assertEqual(set(actual), controls)
        for vector in self.data["vectors"]:
            if vector["name"] not in actual:
                continue
            item = actual[vector["name"]]
            self.assertEqual(item["recordSetHash"], vector["receipt"]["completenessEvidence"]["recordSetHash"])
            self.assertEqual(item["receiptContentHash"], digest(unsigned(vector["receipt"])))
            self.assertEqual(item["verdict"], vector["expected"])
            if vector["expected"] == "pass":
                self.assertEqual(item["winnerBidderClaim"], vector["receipt"]["winner"]["bidderClaim"])
                self.assertEqual(item["winnerBidHash"], vector["receipt"]["winner"]["bidHash"])
            elif "price" in vector["name"] or "decimal" in vector["name"]:
                self.assertEqual(item["malformedPriceCount"], 3)

    def test_every_vector_matches_independent_evaluator(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(Evaluator(vector).evaluate(), vector["expected"])

    def test_attack_cases_are_present(self):
        names = {vector["name"] for vector in self.data["vectors"]}
        required = {
            "complete-demand-absent-auction-mode",
            "complete-demand-explicit-auction-mode",
            "demand-phase-procurement-mode-rejected",
            "procurement-phase-demand-mode-rejected",
            "demand-role-direction-rejected",
            "omitted-better-reveal",
            "selective-discovery-stale-signed-set",
            "finalized-fork-conflict",
            "winning-record-unavailable",
            "signed-lying-winner",
            "unauthorized-selection-receipt-signer",
            "agreement-receipt-substitution",
            "first-acceptable-refused",
            "rule-ref-refused",
            "rule-ref-timeout-refused-before-execution",
            "rule-ref-error-refused-before-execution",
            "late-better-reveal-excluded",
            "invalid-signature-rejects-selection",
            "valid-signed-bidhash-mismatch-excluded",
            "short-salt-reveal-rejects-selection",
            "equal-price-equal-time-bidhash",
            "nonfinite-price-amounts-rejected",
            "snan-and-exponent-price-amounts-rejected",
            "non-string-price-amounts-rejected",
            "malformed-price-shapes-rejected",
            "noncanonical-price-amounts-rejected",
            "noncanonical-decimal-shapes-rejected",
            "zero-and-negative-prices-excluded",
            "long-integer-lowest-price",
            "long-integer-highest-price",
            "long-fraction-lowest-price",
            "long-fraction-highest-price",
            "long-fraction-inclusive-reserve-ceiling",
            "long-fraction-inclusive-reserve-floor",
            "finalized-state-at-reveal-deadline",
            "finalized-state-before-reveal-deadline-rejected",
            "binding-definition-unavailable",
            "definition-content-hash-substitution-rejected",
            "definition-ref-substitution-rejected",
            "self-selected-definition-key-rejected",
            "binding-id-substitution-rejected",
            "binding-version-substitution-rejected",
            "noncanonical-binding-version-rejected",
            "binding-record-ceiling-exceeded",
            "non-usd-listing-matching-bids",
            "non-usd-listing-usd-bids-excluded",
            "non-usd-listing-third-currency-reserve-rejected",
            "resigned-cross-job-artifacts-rejected",
            "resigned-cross-listing-artifacts-rejected",
            "resigned-cross-phase-artifacts-rejected",
            "signed-commit-extra-member-rejected",
            "signed-commit-missing-member-rejected",
            "signed-reveal-extra-member-rejected",
            "signed-reveal-missing-member-rejected",
            "signed-commit-wrong-version-rejected",
            "signed-reveal-wrong-version-rejected",
            "signed-commit-signature-extra-member-rejected",
            "signed-reveal-signature-extra-member-rejected",
            "copied-commitment-as-other-bidder-excluded",
            "cross-channel-commitment-replay-excluded",
            "cross-job-commitment-replay-excluded",
            "cross-listing-commitment-replay-excluded",
            "cross-phase-commitment-replay-excluded",
            "historical-v1-commitment-in-complete-profile-excluded",
            "other-bidder-channel-assignment-rejected",
            "channel-assignment-unavailable",
            "record-signer-bidder-mismatch-rejected",
            "anchor-writer-bidder-mismatch-rejected",
            "premature-reveal-before-commit-deadline-excluded",
            "reveal-at-commit-deadline-admitted",
        }
        self.assertTrue(required.issubset(names))

    def test_demand_controls_pin_absent_and_explicit_modes_and_roles(self):
        vectors = {vector["name"]: vector for vector in self.data["vectors"]}
        absent = vectors["complete-demand-absent-auction-mode"]
        explicit = vectors["complete-demand-explicit-auction-mode"]
        self.assertNotIn("auctionMode", absent["listing"]["parameters"])
        self.assertEqual(explicit["listing"]["parameters"]["auctionMode"], "demand")
        for vector in (absent, explicit):
            winner = vector["receipt"]["winner"]["bidderClaim"]
            roles = {party["role"]: party["primaryClaim"] for party in vector["agreement"]["parties"]}
            self.assertEqual(roles["buyer"], winner)
            self.assertEqual(roles["seller"], vector["listing"]["publisherClaim"])

    def test_authenticated_authority_rows_are_independent_inputs(self):
        vectors = {vector["name"]: vector for vector in self.data["vectors"]}
        for name in (
            "resigned-cross-job-artifacts-rejected",
            "resigned-cross-listing-artifacts-rejected",
            "resigned-cross-phase-artifacts-rejected",
            "self-selected-definition-key-rejected",
            "binding-id-substitution-rejected",
            "binding-version-substitution-rejected",
        ):
            with self.subTest(vector=name):
                vector = vectors[name]
                invocation = vector["context"]["authenticatedInvocation"]
                submitted = vector["receipt"]
                self.assertTrue(invocation["authenticated"])
                self.assertTrue(
                    submitted["jobId"] != invocation["jobId"]
                    or submitted["listingRef"] != invocation["listingRef"]
                    or submitted["phaseKind"] != invocation["phaseKind"]
                    or submitted["candidateSetBinding"] != invocation["candidateSetBinding"]
                )
                self.assertEqual(Evaluator(vector).evaluate(), "fail")

    def test_non_positive_prices_are_excluded_before_selection(self):
        vector = next(
            item for item in self.data["vectors"]
            if item["name"] == "zero-and-negative-prices-excluded"
        )
        excluded = [
            decision for decision in vector["receipt"]["bidDecisions"]
            if decision.get("reason") == "non-positive-price"
        ]
        self.assertEqual(len(excluded), 2)
        self.assertEqual({decision["price"]["amount"] for decision in excluded}, {"0", "-1"})

    def test_long_reserve_bounds_are_exact_and_inclusive(self):
        for name, excluded_count in (
            ("long-fraction-inclusive-reserve-ceiling", 2),
            ("long-fraction-inclusive-reserve-floor", 2),
        ):
            with self.subTest(vector=name):
                vector = next(item for item in self.data["vectors"] if item["name"] == name)
                reserve = vector["listing"]["pricing"]["reservePrice"]
                winner = vector["receipt"]["winner"]
                self.assertEqual(winner["price"], reserve)
                self.assertEqual(
                    sum(
                        decision.get("reason") == "reserve-price"
                        for decision in vector["receipt"]["bidDecisions"]
                    ),
                    excluded_count,
                )

    def test_optional_reserve_is_distinct_from_malformed_present_reserve(self):
        control = next(item for item in self.data["vectors"] if item["name"] == "auction-pricing-without-reserve")
        self.assertEqual(Evaluator(control).evaluate(), "pass")
        for value in (None, [], "1", {"amount": "1"}, {"amount": "0", "currency": "USD"}):
            changed = copy.deepcopy(control)
            changed["listing"]["pricing"]["reservePrice"] = value
            with self.subTest(reserve=value):
                self.assertEqual(Evaluator(changed).evaluate(), "fail")

    def test_unsupported_rules_fail_before_runtime_outcome_is_read(self):
        cases = [
            vector for vector in self.data["vectors"]
            if vector["name"].startswith("rule-ref-")
        ]
        self.assertGreaterEqual(len(cases), 3)
        baseline = None
        for vector in cases:
            verdict = Evaluator(vector).evaluate()
            self.assertEqual(verdict, "fail")
            baseline = verdict if baseline is None else baseline
            self.assertEqual(verdict, baseline)

    def test_spec_and_demos_mapping_pin_fail_closed_boundary(self):
        spec = SPEC.read_text(encoding="utf-8")
        mapping = MAPPING.read_text(encoding="utf-8")
        for rule in range(1, 13):
            self.assertIn(f"(SAC-{rule})", spec)
        self.assertIn("MUST fail before any rule fetch or execution", spec)
        self.assertIn("does not yet supply a `CandidateSetBindingRef`", mapping)
        self.assertIn("MUST NOT treat an Indexer query", mapping)

    def test_historical_v1_commitment_is_frozen_and_current_domain_is_distinct(self):
        spec = SPEC.read_text(encoding="utf-8")
        core = (ROOT / "spec" / "CORE.md").read_text(encoding="utf-8")
        self.assertIn(
            'sha256("dacs-sealed-bid:v1:" || sha256(canonical_JCS(bid)) || salt)',
            spec,
        )
        self.assertIn('dacs-sealed-bid-context:v1:', spec)
        self.assertIn('dacs-sealed-bid-context:v1:', core)
        self.assertIn('dacs-sealed-bid:v1:', core)
        self.assertIn("frozen", core)
        self.assertIn("not interchangeable", spec)

    def test_context_bound_commitment_dispatches_exact_domain(self):
        vectors = {vector["name"]: vector for vector in self.data["vectors"]}
        winner_reveal = vectors["complete-lowest-price"]["receipt"]["winner"]["revealRef"]
        records = vectors["complete-lowest-price"]["context"]["resolvedRecords"]
        reveal = records[winner_reveal["contentHash"]]
        self.assertIn("channelId", reveal)
        self.assertIn("channelId", records[reveal["commitRef"]["contentHash"]])
        self.assertEqual(reveal["bidHash"], bid_hash(reveal["bid"], reveal["salt"], reveal))
        commit = records[reveal["commitRef"]["contentHash"]]
        self.assertEqual(commit["bidHash"], reveal["bidHash"])
        self.assertEqual(commit["channelId"], reveal["channelId"])

    def test_record_signature_covers_channel_id(self):
        vectors = {vector["name"]: vector for vector in self.data["vectors"]}
        vector = vectors["complete-lowest-price"]
        records = vector["context"]["resolvedRecords"]
        reveal = records[vector["receipt"]["winner"]["revealRef"]["contentHash"]]
        key = vector["context"]["recordPublicKeys"][reveal["bidderClaim"]]
        original_signature = reveal["signature"]["value"]
        original_hash = digest(unsigned(reveal))
        self.assertTrue(
            verify(key, original_signature, (RECORD_DOMAIN + original_hash).encode("ascii"))
        )
        tampered = copy.deepcopy(reveal)
        tampered["channelId"] = "chan-tampered"
        tampered_hash = digest(unsigned(tampered))
        self.assertNotEqual(tampered_hash, original_hash)
        self.assertFalse(
            verify(key, original_signature, (RECORD_DOMAIN + tampered_hash).encode("ascii"))
        )

    def test_channel_assignment_and_native_writer_authority_are_distinct(self):
        vectors = {vector["name"]: vector for vector in self.data["vectors"]}
        valid = vectors["complete-lowest-price"]
        assignments = valid["context"]["authenticatedChannelAssignments"]
        admission = valid["context"]["bindingResolution"]["definition"]["admission"]
        records = valid["context"]["resolvedRecords"]
        for entry in valid["receipt"]["entries"]:
            record = records[entry["recordRef"]["contentHash"]]
            assignment = assignments[record["bidderClaim"]]
            self.assertTrue(assignment["authenticated"])
            self.assertEqual(assignment["channelId"], record["channelId"])
            self.assertEqual(
                assignment["members"],
                sorted((valid["listing"]["publisherClaim"], record["bidderClaim"])),
            )
            native_writer = admission["writerBindings"][record["bidderClaim"]]
            self.assertNotEqual(native_writer, record["bidderClaim"])
            self.assertEqual(entry["anchorReceipt"]["writer"], native_writer)

        self.assertEqual(
            Evaluator(vectors["other-bidder-channel-assignment-rejected"]).evaluate(),
            "fail",
        )
        self.assertEqual(
            Evaluator(vectors["channel-assignment-unavailable"]).evaluate(),
            "indeterminate",
        )
        boundary = vectors["reveal-at-commit-deadline-admitted"]
        self.assertEqual(Evaluator(boundary).evaluate(), "pass")
        self.assertIn(
            "admitted-reveal",
            {decision["disposition"] for decision in boundary["receipt"]["recordDecisions"]},
        )

    def test_copied_commitment_excludes_the_copier(self):
        vector = next(
            item for item in self.data["vectors"]
            if item["name"] == "copied-commitment-as-other-bidder-excluded"
        )
        self.assertEqual(Evaluator(vector).evaluate(), "pass")
        records = vector["context"]["resolvedRecords"]
        mismatch_hashes = [
            decision["recordContentHash"]
            for decision in vector["receipt"]["recordDecisions"]
            if decision.get("reason") == "bid-hash-mismatch"
        ]
        self.assertEqual(len(mismatch_hashes), 1)
        copier_claim = records[mismatch_hashes[0]]["bidderClaim"]
        winner = vector["receipt"]["winner"]["bidderClaim"]
        self.assertNotEqual(copier_claim, winner)
        copied_reveal = records[mismatch_hashes[0]]
        winner_reveal = records[vector["receipt"]["winner"]["revealRef"]["contentHash"]]
        self.assertEqual(copied_reveal["bid"], winner_reveal["bid"])
        self.assertEqual(copied_reveal["bidHash"], vector["receipt"]["winner"]["bidHash"])


if __name__ == "__main__":
    unittest.main()
