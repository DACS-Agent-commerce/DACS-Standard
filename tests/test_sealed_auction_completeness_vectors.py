import base64
import copy
import hashlib
import json
import subprocess
import sys
import unittest
from decimal import Decimal, InvalidOperation
from pathlib import Path

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


def bid_hash(bid, salt_text):
    salt = decode_b64url(salt_text)
    return hashlib.sha256(
        b"dacs-sealed-bid:v1:" + hashlib.sha256(canonical(bid)).digest() + salt
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
        if self.listing.get("phaseKind") not in {
            "negotiate-sealed-envelope-complete",
            "negotiate-sealed-envelope-procurement-complete",
        }:
            return "fail"
        if rule not in {"lowest-price", "highest-price"}:
            return "fail"
        if self.receipt.get("selectionRule") != rule:
            return "fail"
        if self.receipt.get("candidateSetBinding") != params.get("candidateSetBinding"):
            return "fail"
        if not self.ctx.get("bindingDefinitionResolved"):
            return "indeterminate"
        if self.receipt.get("sealedSelectionReceiptVersion") != "1":
            return "fail"
        for key, expected in (
            ("jobId", self.listing.get("listingRef") and self.agreement.get("jobId")),
            ("listingRef", self.listing.get("listingRef")),
            ("phaseIndex", self.listing.get("phaseIndex")),
            ("phaseKind", self.listing.get("phaseKind")),
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
        conflicts = self.ctx.get("knownConflictingStates")
        if not isinstance(conflicts, list) or conflicts:
            return "indeterminate"
        if evidence.get("finalizedState") != self.ctx.get("latestFinalizedState"):
            return "indeterminate"
        proof = evidence.get("proof")
        if not isinstance(proof, dict) or not proof.get("value"):
            return "indeterminate"
        public_key = self.ctx.get("bindingPublicKey")
        if not public_key:
            return "indeterminate"
        payload = (BINDING_DOMAIN + digest(binding_payload(self.receipt))).encode("ascii")
        if not verify(public_key, proof.get("value"), payload):
            return "fail"
        return None

    def _derive_decisions(self):
        entries = self.receipt["entries"]
        records = self.ctx.get("resolvedRecords", {})
        public_keys = self.ctx.get("recordPublicKeys", {})
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
            required = {
                "sealedAuctionRecordVersion", "recordKind", "jobId", "listingRef",
                "phaseIndex", "bidderClaim", "bidHash", "createdAt", "signature",
            }
            if not isinstance(record, dict) or not required.issubset(record):
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
                    kind = record.get("recordKind")
                    commit_only = {"commitRef", "bid", "salt"}.isdisjoint(record)
                    reveal_complete = all(field in record for field in ("commitRef", "bid", "salt"))
                    if kind == "commit" and not commit_only:
                        reason = "malformed-record"
                    elif kind == "reveal" and not reveal_complete:
                        reason = "malformed-record"
                    elif kind == "reveal":
                        try:
                            if len(decode_b64url(record["salt"])) < 32:
                                reason = "malformed-record"
                        except (KeyError, TypeError, ValueError):
                            reason = "malformed-record"
                    elif kind not in {"commit", "reveal"}:
                        reason = "malformed-record"
                    if reason is None:
                        receipt = entry.get("anchorReceipt", {})
                        expected_address = logical_address(record["jobId"], kind, record["bidderClaim"], record["bidHash"])
                        if receipt.get("logicalAddress") != expected_address or receipt.get("contentHash") != record_hash or receipt.get("nativeAddress") != ref.get("anchor", {}).get("locator"):
                            reason = "wrong-address"
                        elif receipt.get("state") != "finalized" or receipt.get("observationDisposition") != "established" or not isinstance(receipt.get("blockRef", {}).get("timestamp"), int):
                            reason = "unfinalized"
                        else:
                            timestamp = receipt["blockRef"]["timestamp"]
                            if kind == "commit" and timestamp > commit_deadline:
                                reason = "late-commit"
                            elif kind == "reveal" and timestamp > reveal_deadline:
                                reason = "late-reveal"
                            else:
                                disposition = "admitted-commit" if kind == "commit" else "admitted-reveal"
                                (commits if kind == "commit" else reveals).setdefault(record["bidderClaim"], []).append((entry, record))
            record_decisions.append({
                "recordContentHash": record_hash,
                "disposition": disposition or "excluded",
                **({"reason": reason} if reason else {}),
            })
            if reason in {"malformed-record", "wrong-session", "bad-signature", "wrong-address", "unfinalized"}:
                return "fail"

        bidders = sorted({record.get("bidderClaim") for record in records.values() if isinstance(record, dict) and record.get("bidderClaim")})
        bid_decisions = []
        eligible = []
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
                    opens = bid_hash(reveal["bid"], reveal["salt"])
                except (KeyError, TypeError, ValueError):
                    continue
                if compare_ref(reveal.get("commitRef"), commit_ref) and reveal.get("bidHash") == commit["bidHash"] == opens:
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
            price = reveal.get("bid", {}).get("price", {})
            reason = None
            try:
                amount = Decimal(price.get("amount"))
            except (InvalidOperation, TypeError):
                amount = Decimal(0)
            if price.get("currency") != "USD":
                reason = "currency-mismatch"
            elif amount <= 0:
                reason = "non-positive-price"
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
        direction = Decimal(1) if self.receipt["selectionRule"] == "lowest-price" else Decimal(-1)
        eligible.sort(key=lambda item: (
            item[4] * direction,
            item[0]["anchorReceipt"]["blockRef"]["timestamp"],
            item[1]["bidHash"],
        ))
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
            key in agreement for key in ("agreementVersion", "payeeBoundAgreementVersion")
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
        if buyers[0].get("primaryClaim") != self.listing.get("publisherClaim") or sellers[0].get("primaryClaim") != winner.get("bidderClaim"):
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
        for vector in self.data["vectors"]:
            if vector["name"] not in actual:
                continue
            item = actual[vector["name"]]
            self.assertEqual(item["recordSetHash"], vector["receipt"]["completenessEvidence"]["recordSetHash"])
            self.assertEqual(item["receiptContentHash"], digest(unsigned(vector["receipt"])))
            self.assertEqual(item["winnerBidderClaim"], vector["receipt"]["winner"]["bidderClaim"])
            self.assertEqual(item["winnerBidHash"], vector["receipt"]["winner"]["bidHash"])

    def test_every_vector_matches_independent_evaluator(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(Evaluator(vector).evaluate(), vector["expected"])

    def test_attack_cases_are_present(self):
        names = {vector["name"] for vector in self.data["vectors"]}
        required = {
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
        }
        self.assertTrue(required.issubset(names))

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
        for rule in range(1, 11):
            self.assertIn(f"(SAC-{rule})", spec)
        self.assertIn("MUST fail before any rule fetch or execution", spec)
        self.assertIn("does not yet supply a `CandidateSetBindingRef`", mapping)
        self.assertIn("MUST NOT treat an Indexer query", mapping)


if __name__ == "__main__":
    unittest.main()
