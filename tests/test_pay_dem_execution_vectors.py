"""Execute the DACS-4 §9.5.9 DEM-1..DEM-7 pay-dem execution corpus."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_pay_dem_execution_vectors as generator  # noqa: E402
from jcs import canonicalize  # noqa: E402


VECTORS = ROOT / "conformance/vectors/security/pay-dem-execution-v0.1.json"
GENERATOR = ROOT / "scripts/generate_pay_dem_execution_vectors.py"
SPEC = ROOT / "spec/DACS-4-SETTLE.md"
DEMOS = ROOT / "spec/DEMOS-MAPPING.md"
WORKFLOW = ROOT / ".github/workflows/validate.yml"

# Each guard is one check of the oracle below. Disabling a guard models the
# corresponding wrong implementation; every vector names the guards whose
# removal must change its result.
GUARDS = frozenset({
    # DEM-1
    "first-broadcast-allowed",
    "broadcast-requires-durable-retention",
    "broadcast-requires-complete-retention",
    "retention-bound-to-phase",
    "retained-sender-is-payer",
    "retained-recipient-is-payee",
    "retained-amount-is-phase-amount",
    "signed-transfer-matches-retention",
    "no-cross-phase-reuse",
    # DEM-2 and the DEMOS-MAPPING §A.2 native-send record profile
    "node-profile-pinned",
    "decode-hash",
    "decode-nonce",
    "decode-amount",
    "decode-address",
    "decode-native-send",
    "bind-hash",
    "bind-nonce",
    "bind-block",
    "bind-sender",
    "bind-recipient",
    "bind-amount",
    "bind-requires-inclusion",
    # DEM-3
    "success-branch",
    "success-requires-record",
    "success-requires-exact-confirmed",
    # DEM-4
    "failure-is-permanent",
    "failure-requires-binding",
    "failure-proof-retained",
    "resume-reuses-failure-proof",
    "resume-validates-failure-proof",
    # DEM-5
    "unresolved-authorizes-nothing",
    # DEM-6
    "no-rebroadcast",
    "no-replacement",
    # DEM-7
    "consumer-admits-confirmed",
    "consumer-requires-confirmed-record",
    "consumer-binding",
    "consumer-failed-refutes",
    "consumer-authenticated-contradiction-fails",
    # DEM-7 composed with FV-5, SB-1, SB-2 and PB before delivery
    "delivery-requires-dem7",
    "delivery-requires-authenticated-record",
    "delivery-requires-fv",
    "delivery-requires-sb1",
    "delivery-requires-pb",
    "delivery-sb2-own-admissions",
    "sb2-same-tuple-idempotent",
})

# The expected PC-4 result of each handler class, written out here rather
# than taken from the generator.
HANDLER_WANT = {
    "pass": {
        "ok": True, "errorClass": None, "executionState": "executed",
        "evidence": "success-bft-final", "nextAction": "anchor-success-evidence",
        "onPauseExpiry": None, "retainedHashKept": True,
        "terminalFailureProofRetained": False, "deliveryAuthorized": True,
        "settlementAccounting": True, "broadcastPermitted": False,
        "replacementPermitted": False,
    },
    "fail": {
        "ok": False, "errorClass": "permanent", "executionState": "failed",
        "evidence": "failure-without-settlement-finality", "nextAction": "terminal-failure",
        "onPauseExpiry": None, "retainedHashKept": True,
        "terminalFailureProofRetained": True, "deliveryAuthorized": False,
        "settlementAccounting": False, "broadcastPermitted": False,
        "replacementPermitted": False,
    },
    "indeterminate": {
        "ok": False, "errorClass": "substrate", "executionState": "indeterminate",
        "evidence": "none", "nextAction": "st7-pause-re-read-retained-hash",
        "onPauseExpiry": "failed-substrate-without-replacement", "retainedHashKept": True,
        "terminalFailureProofRetained": False, "deliveryAuthorized": False,
        "settlementAccounting": False, "broadcastPermitted": False,
        "replacementPermitted": False,
    },
}

SAFE_MAX = 2**53 - 1
HASH = re.compile(r"[0-9a-f]{64}")
ADDRESS = re.compile(r"(?:0x)?([0-9a-f]{64})")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)")
RETAINED = {"jobId", "phaseIndex", "txHash", "nonce", "sender", "recipient", "amountOs"}


def _safe_integer(value) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value == int(value)
        and 0 <= value <= SAFE_MAX
    )


def _lenient_integer(value):
    """A permissive implementation: coerce whatever looks numeric."""
    try:
        if isinstance(value, (bool, int, float)):
            return int(value)
        return int(Decimal(str(value).strip()))
    except (InvalidOperation, ValueError, TypeError):
        return None


def _integer(value, guard, off):
    """Profile integer: a safe JSON integer or a canonical decimal string."""
    if guard in off:
        return _lenient_integer(value)
    if _safe_integer(value):
        return int(value)
    if isinstance(value, str) and DECIMAL.fullmatch(value):
        return int(value)
    return None


def _address(value, off):
    if "decode-address" in off:
        return value.strip().lower().removeprefix("0x") if isinstance(value, str) else None
    match = ADDRESS.fullmatch(value) if isinstance(value, str) else None
    return match.group(1) if match else None


def decode(transaction, off, *, executed: bool = True):
    """DEMOS-MAPPING §A.2 native-send projection of a node record (or, with
    ``executed=False``, of a signed transaction), or None."""
    if not isinstance(transaction, dict) or not isinstance(transaction.get("content"), dict):
        return None
    content = transaction["content"]
    projection = {}
    tx_hash = transaction.get("hash")
    if "decode-hash" in off:
        tx_hash = tx_hash.lower().removeprefix("0x") if isinstance(tx_hash, str) else None
    elif not (isinstance(tx_hash, str) and HASH.fullmatch(tx_hash)):
        return None
    projection["txHash"] = tx_hash
    if executed:
        if not _safe_integer(transaction.get("blockNumber")):
            return None
        if not isinstance(transaction.get("status"), str):
            return None
        projection["blockNumber"] = int(transaction["blockNumber"])
        projection["status"] = transaction["status"]
    if "nonce" in content or "decode-nonce" not in off:
        nonce = _integer(content.get("nonce"), "decode-nonce", off)
        if nonce is None:
            return None
        projection["nonce"] = nonce
    amount = _integer(content.get("amount"), "decode-amount", off)
    sender = _address(content.get("from"), off)
    recipient = _address(content.get("to"), off)
    if amount is None or sender is None or recipient is None:
        return None
    if "from_ed25519_address" in content and "decode-address" not in off:
        if _address(content["from_ed25519_address"], off) != sender:
            return None
    if "decode-native-send" not in off:
        data = content.get("data")
        if not (
            content.get("type") == "native"
            and isinstance(data, list)
            and len(data) == 2
            and data[0] == "native"
            and isinstance(data[1], dict)
            and set(data[1]) == {"nativeOperation", "args"}
            and data[1]["nativeOperation"] == "send"
            and isinstance(data[1]["args"], list)
            and len(data[1]["args"]) == 2
            and _address(data[1]["args"][0], off) == recipient
            and isinstance(data[1]["args"][1], str)
            and DECIMAL.fullmatch(data[1]["args"][1])
            and int(data[1]["args"][1]) == amount
        ):
            return None
    projection.update(sender=sender, recipient=recipient, amountOs=amount)
    return projection


def bound(projection, transfer, inclusion, off) -> bool:
    """DEM-2: every retained value plus the observed inclusion block."""
    if projection is None:
        return False
    for guard, field in (
        ("bind-hash", "txHash"),
        ("bind-nonce", "nonce"),
        ("bind-sender", "sender"),
        ("bind-recipient", "recipient"),
        ("bind-amount", "amountOs"),
    ):
        if guard in off or field not in projection:
            continue
        want = int(transfer[field]) if field == "amountOs" else transfer.get(field)
        if projection[field] != want:
            return False
    if "bind-block" in off:
        return True
    block = inclusion.get("blockNumber") if isinstance(inclusion, dict) else None
    if block is None:
        return "bind-requires-inclusion" in off
    return projection["blockNumber"] == block


def pinned(read, off) -> bool:
    return read.get("nodeProfile") == "pinned" or "node-profile-pinned" in off


def is_confirmed(status, off) -> bool:
    if "success-requires-exact-confirmed" in off:
        return isinstance(status, str) and status.lower() in {
            "confirmed", "included", "finalized", "success",
        }
    return status == "confirmed"


def handler_result(expected: str, protocol_input: dict, off) -> tuple[str, dict]:
    want = dict(HANDLER_WANT[expected])
    if expected == "fail":
        if "failure-proof-retained" in off:
            want["terminalFailureProofRetained"] = False
        if "no-replacement" in off:
            want["replacementPermitted"] = True
    if expected == "indeterminate":
        if (
            "unresolved-authorizes-nothing" in off
            and protocol_input["statusIndex"] == "included"
        ):
            want["deliveryAuthorized"] = True
            want["settlementAccounting"] = True
        if "no-rebroadcast" in off and protocol_input["recordRead"]["state"] == "not-found":
            want["broadcastPermitted"] = True
    return expected, want


def classify(protocol_input: dict, off) -> tuple[str, dict]:
    """DEM-2..DEM-6 handler classification of one re-read."""
    if "success-requires-record" in off and protocol_input["statusIndex"] == "included":
        return handler_result("pass", protocol_input, off)
    read = protocol_input["recordRead"]
    record = read.get("record") if read.get("state") == "found" else None
    projection = decode(record, off) if record is not None else None
    status = projection["status"] if projection else None
    is_bound = pinned(read, off) and bound(
        projection,
        protocol_input["retainedTransfer"],
        protocol_input["inclusionObservation"],
        off,
    )
    if is_bound and is_confirmed(status, off) and "success-branch" not in off:
        return handler_result("pass", protocol_input, off)
    if status == "failed" and (is_bound or "failure-requires-binding" in off):
        if "failure-is-permanent" not in off:
            return handler_result("fail", protocol_input, off)
    return handler_result("indeterminate", protocol_input, off)


def valid_failure_proof(proof, transfer, off) -> bool:
    if not (isinstance(proof, dict) and proof.get("classification") == "permanent"):
        return False
    projection = decode(proof.get("record"), off)
    return (
        projection is not None
        and projection["status"] == "failed"
        and bound(projection, transfer, {"blockNumber": proof.get("inclusionBlock")}, off)
    )


def resume(protocol_input: dict, off) -> tuple[str, dict]:
    proof = protocol_input["retainedFailureProof"]
    if proof is not None and "resume-reuses-failure-proof" not in off:
        if "resume-validates-failure-proof" in off or valid_failure_proof(
            proof, protocol_input["retainedTransfer"], off
        ):
            return handler_result("fail", protocol_input, off)
    return classify(protocol_input, off)


def complete_transfer(transfer) -> bool:
    return (
        isinstance(transfer, dict)
        and set(transfer) == RETAINED
        and isinstance(transfer["jobId"], str)
        and transfer["jobId"] != ""
        and _safe_integer(transfer["phaseIndex"])
        and isinstance(transfer["phaseIndex"], int)
        and _safe_integer(transfer["nonce"])
        and isinstance(transfer["nonce"], int)
        and all(
            isinstance(transfer[field], str) and HASH.fullmatch(transfer[field])
            for field in ("txHash", "sender", "recipient")
        )
        and isinstance(transfer["amountOs"], str)
        and DECIMAL.fullmatch(transfer["amountOs"]) is not None
    )


def broadcast_gate(protocol_input: dict, off) -> tuple[str, dict]:
    """DEM-1 retention for the authenticated phase, then DEM-6."""
    refused = ("fail", {"broadcastPermitted": False})
    transfer = protocol_input["retainedTransfer"]
    phase = protocol_input["phase"]
    if not complete_transfer(transfer) and "broadcast-requires-complete-retention" not in off:
        return "error", {"broadcastPermitted": False}
    if protocol_input["broadcastState"] != "never-broadcast":
        if protocol_input["request"] == "broadcast-replacement":
            if "no-replacement" not in off:
                return refused
        elif "no-rebroadcast" not in off:
            return refused
    if "retention-bound-to-phase" not in off and (
        transfer.get("jobId"), transfer.get("phaseIndex")
    ) != (phase["jobId"], phase["phaseIndex"]):
        return refused
    for guard, field, authority in (
        ("retained-sender-is-payer", "sender", "payerPayingKey"),
        ("retained-recipient-is-payee", "recipient", "payeeAddress"),
        ("retained-amount-is-phase-amount", "amountOs", "amountOs"),
    ):
        if guard not in off and transfer.get(field) != phase[authority]:
            return refused
    if "signed-transfer-matches-retention" not in off:
        projection = decode(protocol_input["signedTransaction"], frozenset(), executed=False)
        if projection is None or any(
            projection[field] != (
                _lenient_integer(transfer.get(field)) if field == "amountOs" else transfer.get(field)
            )
            for field in ("txHash", "nonce", "sender", "recipient", "amountOs")
        ):
            return refused
    if protocol_input["hashRetainedForOtherPhases"] and "no-cross-phase-reuse" not in off:
        return refused
    if not protocol_input["retentionDurable"] and (
        "broadcast-requires-durable-retention" not in off
    ):
        return refused
    if "first-broadcast-allowed" in off:
        return refused
    return "pass", {"broadcastPermitted": True}


def dem7(protocol_input: dict, off) -> str:
    """DEM-7 consumer gate, including the payee before delivery."""
    if (
        "consumer-requires-confirmed-record" in off
        and protocol_input["statusIndex"] == "included"
    ):
        return "pass"
    read = protocol_input["recordRead"]
    record = read.get("record") if read.get("state") == "found" else None
    projection = decode(record, off) if record is not None else None
    if projection is None or not pinned(read, off):
        return "indeterminate"
    reference = protocol_input["signedEvidence"]["txRef"]
    phase = protocol_input["phase"]
    expected_values = {
        "txHash": reference["txHash"],
        "blockNumber": reference["blockNumber"],
        "sender": phase["payerPayingKey"],
        "recipient": phase["payeeAddress"],
        "amountOs": int(phase["amountOs"]),
    }
    is_bound = "consumer-binding" in off or all(
        projection[field] == value for field, value in expected_values.items()
    )
    status = projection["status"]
    if is_bound and is_confirmed(status, off):
        return "indeterminate" if "consumer-admits-confirmed" in off else "pass"
    if is_bound and status == "failed":
        return "indeterminate" if "consumer-failed-refutes" in off else "fail"
    if (
        not is_bound
        and read.get("authenticated") is True
        and "consumer-authenticated-contradiction-fails" not in off
    ):
        return "fail"
    return "indeterminate"


def admit(protocol_input: dict, off) -> tuple[str, dict]:
    verdict = dem7(protocol_input, off)
    return verdict, {"dem7GatePassed": verdict == "pass", "deliveryAuthorized": False}


def admit_for_delivery(protocol_input: dict, off) -> tuple[str, dict]:
    gate = dem7(protocol_input, off)

    def result(expected: str) -> tuple[str, dict]:
        return expected, {
            "dem7GatePassed": gate == "pass",
            "deliveryAuthorized": expected == "pass",
            "settlementAccounting": expected == "pass",
        }

    if gate != "pass" and "delivery-requires-dem7" not in off:
        return result(gate)
    if (
        protocol_input["recordRead"].get("authenticated") is not True
        and "delivery-requires-authenticated-record" not in off
    ):
        return result("indeterminate")
    for name in ("fv", "sb1", "pb"):
        verdict = protocol_input["otherGates"][name]
        if verdict != "pass" and f"delivery-requires-{name}" not in off:
            return result(verdict)
    tuple_ = {
        "jobId": protocol_input["phase"]["jobId"],
        "phaseIndex": protocol_input["phase"]["phaseIndex"],
    }
    others = [
        admitted for admitted in protocol_input["consumerAdmissions"]
        if admitted != tuple_ or "sb2-same-tuple-idempotent" in off
    ]
    if others and "delivery-sb2-own-admissions" not in off:
        return result("indeterminate")
    return result("pass")


OPERATIONS = {
    "classify-execution": classify,
    "resume-phase": resume,
    "broadcast-gate": broadcast_gate,
    "admit-evidence": admit,
    "admit-for-delivery": admit_for_delivery,
}


def evaluate(vector: dict, off=frozenset()) -> tuple[str, dict]:
    return OPERATIONS[vector["operation"]](vector["protocolInput"], frozenset(off))


def flipping_guards(vector: dict) -> list[str]:
    baseline = evaluate(vector)
    return sorted(guard for guard in GUARDS if evaluate(vector, {guard}) != baseline)


class PayDemExecutionVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {vector["name"]: vector for vector in cls.data["vectors"]}

    def test_committed_file_is_deterministic(self):
        self.assertEqual(VECTORS.read_text(encoding="utf-8"), generator.rendered())

    def test_corpus_hash_is_jcs_bound_and_names_are_unique(self):
        encoded = canonicalize(self.data["vectors"]).encode("utf-8")
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), self.data["hash"])
        self.assertEqual(self.data["count"], len(self.data["vectors"]))
        self.assertEqual(self.data["count"], len(self.cases))
        # Every vector survives a JCS round trip unchanged, so a JavaScript
        # JSON.parse reader sees the same values as this oracle.
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                self.assertEqual(vector, json.loads(canonicalize(vector)))

    def test_cli_check_accepts_the_committed_file_and_rejects_a_stale_one(self):
        ok = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(0, ok.returncode, ok.stdout + ok.stderr)
        self.assertIn(f"OK ({self.data['count']} vectors)", ok.stdout)
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "scripts").mkdir()
            for name in ("generate_pay_dem_execution_vectors.py", "jcs.py"):
                shutil.copy(ROOT / "scripts" / name, root / "scripts" / name)
            output = root / "conformance/vectors/security/pay-dem-execution-v0.1.json"
            output.parent.mkdir(parents=True)
            output.write_text(VECTORS.read_text(encoding="utf-8").replace('"pass"', '"fail"', 1), encoding="utf-8")
            script = root / "scripts/generate_pay_dem_execution_vectors.py"
            stale = subprocess.run(
                [sys.executable, str(script), "--check"],
                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(1, stale.returncode, stale.stdout + stale.stderr)
            self.assertIn("stale", stale.stdout)
            output.unlink()
            missing = subprocess.run(
                [sys.executable, str(script), "--check"],
                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(1, missing.returncode, missing.stdout + missing.stderr)
            written = subprocess.run(
                [sys.executable, str(script), "--write"],
                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(0, written.returncode, written.stdout + written.stderr)
            self.assertEqual(VECTORS.read_text(encoding="utf-8"), output.read_text(encoding="utf-8"))

    def test_every_vector_executes_to_its_pinned_result(self):
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                expected, want = evaluate(vector)
                self.assertEqual(vector["expected"], expected)
                self.assertEqual(vector["want"], want)

    def test_handler_results_use_pc4_classes(self):
        for vector in self.data["vectors"]:
            if vector["operation"] not in {"classify-execution", "resume-phase"}:
                continue
            with self.subTest(name=vector["name"]):
                self.assertEqual(HANDLER_WANT[vector["expected"]], vector["want"])
                self.assertIn(vector["want"]["errorClass"], {None, "permanent", "substrate"})

    def test_every_vector_fails_when_each_named_guard_is_removed(self):
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                self.assertTrue(vector["guards"], "every vector names a guard")
                self.assertEqual(vector["guards"], flipping_guards(vector))

    def test_every_guard_is_load_bearing(self):
        named = {guard for vector in self.data["vectors"] for guard in vector["guards"]}
        self.assertEqual(GUARDS, named)

    def test_every_dem_rule_is_defined_and_exercised(self):
        spec = SPEC.read_text(encoding="utf-8")
        defined = {int(n) for n in re.findall(r"\(DEM-(\d+)\)", spec)}
        self.assertEqual(set(range(1, 8)), defined)
        cited = set()
        for vector in self.data["vectors"]:
            cited.update(int(n) for n in re.findall(r"DEM-(\d+)", vector["rule"]))
        self.assertEqual(defined, cited)

    def test_live_node2_records_classify_by_their_recorded_status(self):
        self.assertEqual("pass", evaluate(self.cases["node2-confirmed-record"])[0])
        self.assertEqual("fail", evaluate(self.cases["node2-included-failed-record"])[0])
        self.assertEqual("included", self.cases["node2-included-failed-record"]["protocolInput"]["statusIndex"])
        # The same live records, retained in raw wire types instead of the
        # profile projection, would never bind.
        raw = dict(self.cases["node2-confirmed-record"]["protocolInput"])
        record = raw["recordRead"]["record"]
        raw["retainedTransfer"] = dict(
            raw["retainedTransfer"], nonce=record["content"]["nonce"], amountOs=record["content"]["amount"],
        )
        self.assertEqual("indeterminate", classify(raw, frozenset())[0])

    def test_status_index_uses_node_labels(self):
        labels = {vector["protocolInput"].get("statusIndex") for vector in self.data["vectors"]}
        self.assertEqual({None, "included", "pending", "unknown"}, labels)

    def test_inclusion_alone_never_succeeds_or_authorizes(self):
        for vector in self.data["vectors"]:
            if vector["operation"] == "broadcast-gate":
                continue
            read = vector["protocolInput"]["recordRead"]
            record = read.get("record") if read.get("state") == "found" else None
            if isinstance(record, dict) and record.get("status") == "confirmed":
                continue
            with self.subTest(name=vector["name"]):
                self.assertNotEqual("pass", vector["expected"])
                self.assertFalse(vector["want"].get("deliveryAuthorized"))

    def test_dem7_alone_never_authorizes_delivery(self):
        for vector in self.data["vectors"]:
            if vector["operation"] == "admit-evidence":
                with self.subTest(name=vector["name"]):
                    self.assertFalse(vector["want"]["deliveryAuthorized"])
        delivered = {
            vector["name"] for vector in self.data["vectors"]
            if vector["want"].get("deliveryAuthorized") and vector["operation"] == "admit-for-delivery"
        }
        self.assertEqual({"delivery-after-all-gates", "delivery-same-tuple-readmitted"}, delivered)
        for name in delivered:
            protocol_input = self.cases[name]["protocolInput"]
            self.assertIs(True, protocol_input["recordRead"]["authenticated"])
            self.assertEqual({"fv": "pass", "sb1": "pass", "pb": "pass"}, protocol_input["otherGates"])

    def test_inclusion_only_implementation_is_rejected(self):
        wrong = {
            vector["name"]
            for vector in self.data["vectors"]
            if evaluate(vector, {"success-requires-record"}) != evaluate(vector)
        }
        self.assertIn("included-failed", wrong)
        self.assertIn("node2-included-failed-record", wrong)
        self.assertIn("included-record-not-found", wrong)
        consumer = {
            vector["name"]
            for vector in self.data["vectors"]
            if evaluate(vector, {"consumer-requires-confirmed-record"}) != evaluate(vector)
        }
        self.assertIn("consumer-included-only-refused", consumer)
        self.assertIn("consumer-failed-fails", consumer)
        self.assertIn("delivery-dem7-pending", consumer)

    def test_handler_never_permits_a_second_or_replacement_broadcast(self):
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                want = vector["want"]
                if vector["operation"] in {"classify-execution", "resume-phase"}:
                    self.assertFalse(want["broadcastPermitted"])
                    self.assertFalse(want["replacementPermitted"])
                if vector["operation"] == "broadcast-gate" and want["broadcastPermitted"]:
                    self.assertEqual(
                        "never-broadcast", vector["protocolInput"]["broadcastState"]
                    )

    def test_proven_failure_is_durable_and_omits_settlement_finality(self):
        for vector in self.data["vectors"]:
            if vector["operation"] in {"classify-execution", "resume-phase"} and (
                vector["expected"] == "fail"
            ):
                with self.subTest(name=vector["name"]):
                    want = vector["want"]
                    self.assertEqual("permanent", want["errorClass"])
                    self.assertTrue(want["terminalFailureProofRetained"])
                    self.assertEqual("failure-without-settlement-finality", want["evidence"])

    def test_spec_mapping_and_workflow_make_the_rules_load_bearing(self):
        spec = SPEC.read_text(encoding="utf-8")
        demos = DEMOS.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("status is exactly `confirmed`", spec)
        self.assertIn("MUST NOT broadcast it again or broadcast a replacement transfer", spec)
        self.assertIn("verify the included\n  transaction record under §9.5.9 DEM-7", spec)
        self.assertIn('`errorClass: "substrate"`', spec)
        self.assertIn("(`pay-evm-erc20`, `pay-solana-spl`, `pay-ap2`, `pay-x402`, `pay-dem`)", spec)
        self.assertNotIn('the tx reached the terminal "included" state', spec)
        self.assertNotIn("differently typed", spec)
        self.assertIn("DEM-2 and DEM-3", demos)
        self.assertIn("61b8e75aa8db5e408c49e1c3a89db4d673f45578", demos)
        self.assertIn("**Native-send record profile (normative).**", demos)
        self.assertIn("generate_pay_dem_execution_vectors.py --check", workflow)


if __name__ == "__main__":
    unittest.main()
