import base64
import hashlib
import json
import subprocess
import unittest
from pathlib import Path
from urllib.parse import quote, unquote_to_bytes

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "settlement-event-identity-v0.6.json"
)
GENERATOR = ROOT / "scripts" / "generate_settlement_event_identity_vectors.py"
SPEC = ROOT / "spec" / "DACS-4-SETTLE.md"
DOMAIN = "dacs-evidence:v1:"
MAX_SAFE_INTEGER = 9_007_199_254_740_991
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def hash_hex(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def payment_anchor(job_id, rail_id, phase_index):
    encoded_rail_id = quote(rail_id, safe="-._~")
    return f"dacs4:payment:{job_id}:{encoded_rail_id}:{phase_index}"


def parse_payment_anchor(value):
    if not isinstance(value, str):
        raise ValueError("payment anchor must be a string")
    parts = value.split(":")
    if len(parts) == 6:
        if parts.pop() != "resolved":
            raise ValueError("unknown payment-anchor suffix")
    if len(parts) != 5 or parts[:2] != ["dacs4", "payment"]:
        raise ValueError("malformed payment anchor")
    _, _, job_id, encoded_rail_id, phase_text = parts
    if not job_id or not encoded_rail_id:
        raise ValueError("empty payment-anchor segment")
    try:
        rail_id = unquote_to_bytes(encoded_rail_id).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("railId is not UTF-8") from exc
    if quote(rail_id, safe="-._~") != encoded_rail_id:
        raise ValueError("railId is not canonical CF-4")
    if not phase_text.isascii() or not phase_text.isdecimal():
        raise ValueError("phaseIndex is not decimal ASCII")
    phase_index = int(phase_text)
    if str(phase_index) != phase_text or not safe_nonnegative_int(phase_index):
        raise ValueError("phaseIndex is not canonical")
    return job_id, rail_id, phase_index


def b64url_decode(value):
    if not isinstance(value, str) or "=" in value:
        raise ValueError("non-canonical Base64URL")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def base58_decode(value):
    if not isinstance(value, str) or not value:
        raise ValueError("invalid base58")
    number = 0
    for char in value:
        if char not in BASE58_ALPHABET:
            raise ValueError("invalid base58")
        number = number * 58 + BASE58_ALPHABET.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + raw


def signature_valid(evidence, public_key):
    signature = evidence.get("signature")
    if not isinstance(signature, dict):
        return False
    if signature.get("algorithm") != "ed25519":
        return False
    try:
        unsigned = {key: value for key, value in evidence.items() if key != "signature"}
        digest = hash_hex(unsigned)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            b64url_decode(signature.get("value")),
            (DOMAIN + digest).encode("ascii"),
        )
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def safe_nonnegative_int(value, *, positive=False):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and (value > 0 if positive else value >= 0)
        and value <= MAX_SAFE_INTEGER
    )


def canonical_evm_hash(value):
    if not isinstance(value, str):
        raise ValueError("tx hash is not a string")
    normalized = value[2:] if value.startswith(("0x", "0X")) else value
    if len(normalized) != 64:
        raise ValueError("tx hash width")
    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError("tx hash hex") from exc
    return normalized.lower()


def semantic_match(event, context, evidence):
    context_amount = context.get("amount")
    evidence_amount = evidence.get("paymentAmount")
    return (
        isinstance(event, dict)
        and isinstance(context_amount, dict)
        and isinstance(evidence_amount, dict)
        and event.get("asset") == context.get("asset")
        and event.get("payer") == context.get("payer")
        and event.get("payee") == context.get("payee")
        and event.get("amount") == context_amount.get("amount")
        and event.get("amount") == evidence_amount.get("amount")
        and evidence_amount.get("currency") == context_amount.get("currency")
    )


def parse_ref(ref):
    if not isinstance(ref, dict):
        return "error", None
    kind = ref.get("kind")
    if kind == "evm-event":
        if set(ref) != {"kind", "chainId", "txHash", "logIndex"}:
            return "error", None
        if not safe_nonnegative_int(ref.get("chainId"), positive=True):
            return "error", None
        if not safe_nonnegative_int(ref.get("logIndex")):
            return "error", None
        try:
            tx_hash = canonical_evm_hash(ref.get("txHash"))
        except ValueError:
            return "error", None
        if ref["txHash"] != tx_hash:
            return "error", None
        return "current-evm", {
            "chainId": ref["chainId"], "txHash": tx_hash, "index": ref["logIndex"]
        }
    if kind == "solana-instruction":
        if set(ref) != {"kind", "cluster", "signature", "instructionIndex"}:
            return "error", None
        if ref.get("cluster") not in {"mainnet", "devnet", "testnet"}:
            return "error", None
        if not safe_nonnegative_int(ref.get("instructionIndex")):
            return "error", None
        try:
            if len(base58_decode(ref.get("signature"))) != 64:
                return "error", None
        except ValueError:
            return "error", None
        return "current-solana", {
            "cluster": ref["cluster"],
            "signature": ref["signature"],
            "index": ref["instructionIndex"],
        }
    if kind == "x402-event":
        required = {
            "kind", "httpResource", "paymentReceiptHash", "settlementTxHash",
            "chainId", "logIndex", "protocolVersion",
        }
        if set(ref) != required:
            return "error", None
        if not safe_nonnegative_int(ref.get("chainId"), positive=True):
            return "error", None
        if not safe_nonnegative_int(ref.get("logIndex")):
            return "error", None
        if not isinstance(ref.get("paymentReceiptHash"), str) or len(ref["paymentReceiptHash"]) != 64:
            return "error", None
        try:
            bytes.fromhex(ref["paymentReceiptHash"])
            tx_hash = canonical_evm_hash(ref.get("settlementTxHash"))
        except ValueError:
            return "error", None
        if ref["paymentReceiptHash"].lower() != ref["paymentReceiptHash"]:
            return "error", None
        if ref["settlementTxHash"] != tx_hash:
            return "error", None
        return "current-x402", {
            "chainId": ref["chainId"], "txHash": tx_hash, "index": ref["logIndex"]
        }
    if kind == "evm":
        if set(ref) != {"kind", "chainId", "txHash"}:
            return "error", None
        if not safe_nonnegative_int(ref.get("chainId"), positive=True):
            return "error", None
        try:
            tx_hash = canonical_evm_hash(ref.get("txHash"))
        except ValueError:
            return "error", None
        return "legacy-evm", {"chainId": ref["chainId"], "txHash": tx_hash}
    if kind == "solana":
        if set(ref) != {"kind", "cluster", "signature"}:
            return "error", None
        try:
            if len(base58_decode(ref.get("signature"))) != 64:
                return "error", None
        except ValueError:
            return "error", None
        if ref.get("cluster") not in {"mainnet", "devnet", "testnet"}:
            return "error", None
        return "legacy-solana", {
            "cluster": ref["cluster"], "signature": ref["signature"]
        }
    if kind == "x402":
        required = {"kind", "httpResource", "paymentReceiptHash", "protocolVersion"}
        optional = {"settlementTxHash", "chainId"}
        if not required <= set(ref) or not set(ref) <= required | optional:
            return "error", None
        receipt_hash = ref.get("paymentReceiptHash")
        if not isinstance(ref.get("httpResource"), str) or not ref["httpResource"]:
            return "error", None
        if not isinstance(receipt_hash, str) or len(receipt_hash) != 64:
            return "error", None
        try:
            bytes.fromhex(receipt_hash)
        except ValueError:
            return "error", None
        if receipt_hash.lower() != receipt_hash:
            return "error", None
        protocol_version = ref.get("protocolVersion")
        if (
            not isinstance(protocol_version, str)
            or not protocol_version.isdecimal()
            or str(int(protocol_version)) != protocol_version
        ):
            return "error", None
        parsed = {"paymentReceiptHash": receipt_hash}
        if "settlementTxHash" in ref:
            try:
                parsed["signedTxHash"] = canonical_evm_hash(ref["settlementTxHash"])
            except ValueError:
                return "error", None
        if "chainId" in ref:
            if not safe_nonnegative_int(ref["chainId"], positive=True):
                return "error", None
            parsed["signedChainId"] = ref["chainId"]
        return "legacy-x402", parsed
    return "error", None


def event_in_envelope(event, mode, parsed):
    if mode in {"current-evm", "current-x402", "legacy-evm", "legacy-x402"}:
        return (
            event.get("ledger") == "evm"
            and event.get("chainId") == parsed["chainId"]
            and event.get("txHash") == parsed["txHash"]
        )
    return (
        event.get("ledger") == "solana"
        and event.get("cluster") == parsed["cluster"]
        and event.get("signature") == parsed["signature"]
    )


def event_index(event, mode):
    return (
        event.get("instructionIndex")
        if mode in {"current-solana", "legacy-solana"}
        else event.get("logIndex")
    )


def settlement_key(mode, parsed, index):
    if mode in {"current-evm", "current-x402", "legacy-evm", "legacy-x402"}:
        return f"evm:{parsed['chainId']}:{parsed['txHash']}:{index}"
    return f"solana:{parsed['cluster']}:{parsed['signature']}:{index}"


def evaluate(vector, public_key):
    evidence = vector.get("settlementEvidence")
    if not isinstance(evidence, dict) or not signature_valid(evidence, public_key):
        return "fail"
    if (
        evidence.get("outcome") != "success"
        or not isinstance(evidence.get("jobId"), str)
        or not evidence["jobId"]
    ):
        return "error"
    refs = evidence.get("paymentTxRefs")
    if not isinstance(refs, list) or len(refs) != 1:
        return "error"
    mode, parsed = parse_ref(refs[0])
    if mode == "error":
        return "error"

    phase_index = vector.get("phaseIndex")
    if not safe_nonnegative_int(phase_index):
        return "error"
    context = vector.get("verificationContext")
    if not isinstance(context, dict):
        return "error"
    rail_id = context.get("railId")
    if not isinstance(rail_id, str) or not rail_id:
        return "error"

    # The evidence signature authenticates evidence.jobId, but it does not authenticate
    # where the record was published. Before SB-1 projection, independently bind the
    # complete PC-2 tuple to the evidence, authenticated phase/agreement rail context,
    # and BundlePhaseEntry index. A valid ST-8 resolution may add only the fixed suffix.
    anchor = vector.get("anchorAddress")
    try:
        anchor_tuple = parse_payment_anchor(anchor)
    except ValueError:
        return "error"
    if anchor_tuple != (evidence["jobId"], rail_id, phase_index):
        return "fail"

    ledger_events = vector.get("ledgerEvents")
    if ledger_events is None:
        return "indeterminate"
    if not isinstance(ledger_events, list):
        return "error"
    if mode in {"current-x402", "legacy-x402"}:
        receipt = context.get("x402Receipt")
        ref = refs[0]
        if not isinstance(receipt, dict) or receipt.get("verified") is not True:
            return "indeterminate"
        if receipt.get("paymentReceiptHash") != ref.get("paymentReceiptHash"):
            return "fail"
        try:
            receipt_tx_hash = canonical_evm_hash(receipt.get("settlementTxHash"))
        except ValueError:
            return "fail"
        receipt_chain_id = receipt.get("chainId")
        if not safe_nonnegative_int(receipt_chain_id, positive=True):
            return "fail"
        if mode == "current-x402":
            if (
                receipt_tx_hash != ref.get("settlementTxHash")
                or receipt_chain_id != ref.get("chainId")
            ):
                return "fail"
        else:
            if (
                ("signedTxHash" in parsed and parsed["signedTxHash"] != receipt_tx_hash)
                or ("signedChainId" in parsed and parsed["signedChainId"] != receipt_chain_id)
            ):
                return "fail"
            parsed["txHash"] = receipt_tx_hash
            parsed["chainId"] = receipt_chain_id

    envelope_events = [
        item for item in ledger_events
        if isinstance(item, dict) and event_in_envelope(item, mode, parsed)
    ]
    if mode.startswith("current-"):
        selected = [item for item in envelope_events if event_index(item, mode) == parsed["index"]]
        if len(selected) != 1 or not semantic_match(selected[0], context, evidence):
            return "fail"
        index = parsed["index"]
    else:
        matching = [
            item for item in envelope_events
            if semantic_match(item, context, evidence)
        ]
        if not matching:
            return "fail"
        if len(matching) != 1:
            return "indeterminate"
        index = event_index(matching[0], mode)
        if not safe_nonnegative_int(index):
            return "error"

    key = settlement_key(mode, parsed, index)
    expected_key = vector.get("expectedSettlementTxId")
    if expected_key is not None and key != expected_key:
        return "fail"
    prior = vector.get("priorClaims")
    if prior is None:
        return "indeterminate"
    if not isinstance(prior, dict):
        return "error"
    binding = {"jobId": evidence["jobId"], "phaseIndex": phase_index}
    if key in prior and prior[key] != binding:
        return "fail"
    return "pass"


class SettlementEventIdentityVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.public_key = bytes.fromhex(cls.document["publicKey"])

    def test_generator_is_deterministic(self):
        subprocess.run(
            ["python3", str(GENERATOR), "--check"],
            cwd=ROOT,
            check=True,
        )

    def test_header_count_hash_and_unique_names(self):
        vectors = self.document["vectors"]
        self.assertEqual(self.document["count"], len(vectors))
        self.assertEqual(self.document["hash"], hash_hex(vectors))
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_all_vectors_execute(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(evaluate(vector, self.public_key), vector["expected"])

    def test_every_untampered_evidence_signature_is_real(self):
        tampered = {"event-discriminator-stripping", "cross-type-signature-replay"}
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                valid = signature_valid(vector["settlementEvidence"], self.public_key)
                self.assertEqual(valid, vector["name"] not in tampered)

    def test_signed_amount_mismatch_rejection_preserves_valid_signature(self):
        vector = next(
            item for item in self.document["vectors"]
            if item["name"] == "signed-evidence-amount-ledger-mismatch"
        )
        self.assertTrue(signature_valid(vector["settlementEvidence"], self.public_key))
        self.assertEqual(vector["settlementEvidence"]["paymentAmount"]["amount"], "5")
        self.assertEqual(vector["ledgerEvents"][0]["amount"], "6")
        self.assertEqual(evaluate(vector, self.public_key), "fail")

    def test_anchor_tuple_mismatch_rejection_preserves_valid_signature(self):
        names = {
            "payment-anchor-job-mismatch",
            "payment-anchor-rail-mismatch",
            "payment-anchor-phase-index-mismatch",
        }
        vectors = {
            item["name"]: item for item in self.document["vectors"]
            if item["name"] in names
        }
        self.assertEqual(set(vectors), names)
        for name, vector in vectors.items():
            with self.subTest(vector=name):
                self.assertTrue(signature_valid(vector["settlementEvidence"], self.public_key))
                self.assertEqual(evaluate(vector, self.public_key), "fail")

    def test_cf4_rail_segment_is_canonical_before_anchor_comparison(self):
        vector = next(
            item for item in self.document["vectors"]
            if item["name"] == "payment-anchor-cf4-encoded-rail"
        )
        self.assertEqual(
            vector["anchorAddress"],
            "dacs4:payment:job-315-a:evm-erc20%3A8453%3AUSDC:0",
        )
        self.assertEqual(evaluate(vector, self.public_key), "pass")

        noncanonical = dict(
            vector,
            anchorAddress="dacs4:payment:job-315-a:evm-erc20%3a8453%3aUSDC:0",
        )
        self.assertEqual(evaluate(noncanonical, self.public_key), "error")

    def test_required_issue_315_cases_are_present(self):
        names = {vector["name"] for vector in self.document["vectors"]}
        required = {
            "current-evm-log-index",
            "current-solana-instruction-index",
            "batched-evm-transfer-distinct-key",
            "same-event-second-job-rejected",
            "current-event-index-missing",
            "legacy-out-of-band-index-not-authority",
            "signed-index-ledger-mismatch",
            "legacy-unambiguous-replay",
            "legacy-ambiguous-replay",
            "event-discriminator-stripping",
            "cross-type-signature-replay",
            "signed-evidence-amount-ledger-mismatch",
            "legacy-x402-unambiguous-replay",
            "legacy-x402-no-matching-event",
            "legacy-x402-ambiguous-replay",
            "legacy-x402-ledger-unavailable",
            "legacy-x402-receipt-hash-mismatch",
            "legacy-x402-transaction-mismatch",
            "legacy-x402-network-mismatch",
            "legacy-x402-out-of-band-index-not-authority",
            "payment-anchor-job-mismatch",
            "payment-anchor-rail-mismatch",
            "payment-anchor-phase-index-mismatch",
            "payment-anchor-cf4-encoded-rail",
        }
        self.assertTrue(required <= names)

    def test_positive_projection_vectors_pin_exact_keys(self):
        by_name = {vector["name"]: vector for vector in self.document["vectors"]}
        for name in (
            "current-evm-log-index",
            "current-solana-instruction-index",
            "batched-evm-transfer-distinct-key",
            "legacy-unambiguous-replay",
            "current-x402-event",
            "legacy-x402-unambiguous-replay",
        ):
            with self.subTest(vector=name):
                key = by_name[name].get("expectedSettlementTxId")
                self.assertIsInstance(key, str)
                self.assertTrue(key.startswith(("evm:", "solana:")))

    def test_spec_pins_signed_projection_and_legacy_rule(self):
        spec = SPEC.read_text(encoding="utf-8")
        for text in (
            'kind: "evm-event"; chainId: number; txHash: string; logIndex: number',
            'kind: "solana-instruction"; cluster:',
            'kind: "x402-event"; httpResource:',
            "Exactly one matching event permits that event's authenticated index",
            "A caller-supplied index, cache annotation, or indexer field",
            "MUST NOT strip or substitute the discriminator",
            "MUST compare the complete PC-2 logical-address tuple",
        ):
            self.assertIn(text, spec)


if __name__ == "__main__":
    unittest.main()
