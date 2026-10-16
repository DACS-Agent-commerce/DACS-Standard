"""Execute the DACS-4 §9.5.9 DEM-1..DEM-7 pay-dem execution corpus."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_pay_dem_execution_vectors as generator  # noqa: E402


VECTORS = ROOT / "conformance/vectors/security/pay-dem-execution-v0.1.json"
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
    # DEM-2
    "bind-hash",
    "bind-nonce",
    "bind-block",
    "bind-sender",
    "bind-recipient",
    "bind-amount",
    "bind-exact-type",
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
})

RECORD_TYPES = {
    "txHash": str, "nonce": int, "blockNumber": int,
    "sender": str, "recipient": str, "amountOs": str,
}
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)")


def same(left, right, off) -> bool:
    if "bind-exact-type" in off:
        return left == right
    return type(left) is type(right) and left == right


def bound(record, transfer, inclusion, off) -> bool:
    """DEM-2: every retained value plus the observed inclusion block."""
    if not isinstance(record, dict):
        return False
    for guard, field in (
        ("bind-hash", "txHash"),
        ("bind-nonce", "nonce"),
        ("bind-sender", "sender"),
        ("bind-recipient", "recipient"),
        ("bind-amount", "amountOs"),
    ):
        if guard in off:
            continue
        if field not in record or not same(record[field], transfer.get(field), off):
            return False
    if "bind-block" in off:
        return True
    block = inclusion.get("blockNumber") if isinstance(inclusion, dict) else None
    if block is None:
        return "bind-requires-inclusion" in off
    return "blockNumber" in record and same(record["blockNumber"], block, off)


def is_confirmed(status, off) -> bool:
    if "success-requires-exact-confirmed" in off:
        return isinstance(status, str) and status.lower() in {
            "confirmed", "included", "finalized", "success",
        }
    return status == "confirmed"


def handler_result(expected: str, protocol_input: dict, off) -> tuple[str, dict]:
    want = generator.handler_want(expected)
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
    status = record.get("status") if isinstance(record, dict) else None
    is_bound = bound(
        record,
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
    return (
        isinstance(proof, dict)
        and proof.get("classification") == "permanent"
        and isinstance(proof.get("record"), dict)
        and proof["record"].get("status") == "failed"
        and bound(proof["record"], transfer, {"blockNumber": proof.get("inclusionBlock")}, off)
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
        and set(transfer) == {"txHash", "nonce", "sender", "recipient", "amountOs"}
        and all(
            isinstance(transfer[field], RECORD_TYPES[field])
            and not isinstance(transfer[field], bool)
            for field in transfer
        )
        and transfer["nonce"] >= 0
        and DECIMAL.fullmatch(transfer["amountOs"]) is not None
    )


def broadcast_gate(protocol_input: dict, off) -> tuple[str, dict]:
    refused = ("fail", {"broadcastPermitted": False})
    if (
        not complete_transfer(protocol_input["retainedTransfer"])
        and "broadcast-requires-complete-retention" not in off
    ):
        return "error", {"broadcastPermitted": False}
    if protocol_input["broadcastState"] != "never-broadcast":
        if protocol_input["request"] == "broadcast-replacement":
            if "no-replacement" not in off:
                return refused
        elif "no-rebroadcast" not in off:
            return refused
    if not protocol_input["retentionDurable"] and (
        "broadcast-requires-durable-retention" not in off
    ):
        return refused
    if "first-broadcast-allowed" in off:
        return refused
    return "pass", {"broadcastPermitted": True}


def admit(protocol_input: dict, off) -> tuple[str, dict]:
    """DEM-7 consumer admission, including the payee before delivery."""

    def result(expected: str) -> tuple[str, dict]:
        return expected, {
            "admitted": expected == "pass",
            "deliveryAuthorized": expected == "pass",
        }

    if (
        "consumer-requires-confirmed-record" in off
        and protocol_input["statusIndex"] == "included"
    ):
        return result("pass")
    read = protocol_input["recordRead"]
    record = read.get("record") if read.get("state") == "found" else None
    if not isinstance(record, dict):
        return result("indeterminate")
    reference = protocol_input["signedEvidence"]["txRef"]
    phase = protocol_input["phase"]
    expected_values = {
        "txHash": reference["txHash"],
        "blockNumber": reference["blockNumber"],
        "sender": phase["payer"],
        "recipient": phase["payee"],
        "amountOs": phase["amountOs"],
    }
    is_bound = "consumer-binding" in off or all(
        field in record and same(record[field], value, off)
        for field, value in expected_values.items()
    )
    status = record.get("status")
    if is_bound and is_confirmed(status, off):
        return result("indeterminate" if "consumer-admits-confirmed" in off else "pass")
    if is_bound and status == "failed":
        return result("indeterminate" if "consumer-failed-refutes" in off else "fail")
    well_typed = all(
        isinstance(record.get(field), RECORD_TYPES[field]) for field in expected_values
    )
    if (
        not is_bound
        and read.get("authenticated") is True
        and well_typed
        and "consumer-authenticated-contradiction-fails" not in off
    ):
        return result("fail")
    return result("indeterminate")


OPERATIONS = {
    "classify-execution": classify,
    "resume-phase": resume,
    "broadcast-gate": broadcast_gate,
    "admit-evidence": admit,
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

    def test_every_vector_executes_to_its_pinned_result(self):
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                expected, want = evaluate(vector)
                self.assertEqual(vector["expected"], expected)
                self.assertEqual(vector["want"], want)

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

    def test_inclusion_only_implementation_is_rejected(self):
        wrong = {
            vector["name"]
            for vector in self.data["vectors"]
            if evaluate(vector, {"success-requires-record"}) != evaluate(vector)
        }
        self.assertIn("included-failed", wrong)
        self.assertIn("included-record-not-found", wrong)
        consumer = {
            vector["name"]
            for vector in self.data["vectors"]
            if evaluate(vector, {"consumer-requires-confirmed-record"}) != evaluate(vector)
        }
        self.assertIn("consumer-included-only-refused", consumer)
        self.assertIn("consumer-failed-fails", consumer)

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
                    self.assertEqual("permanent", want["handlerResult"])
                    self.assertTrue(want["terminalFailureProofRetained"])
                    self.assertEqual("failure-without-settlement-finality", want["evidence"])

    def test_spec_mapping_and_workflow_make_the_rules_load_bearing(self):
        spec = SPEC.read_text(encoding="utf-8")
        demos = DEMOS.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("status is exactly `confirmed`", spec)
        self.assertIn("MUST NOT broadcast it again or broadcast a replacement transfer", spec)
        self.assertIn("verify the included\n  transaction record under §9.5.9 DEM-7", spec)
        self.assertNotIn('the tx reached the terminal "included" state', spec)
        self.assertIn("DEM-2 and DEM-3", demos)
        self.assertIn("generate_pay_dem_execution_vectors.py --check", workflow)


if __name__ == "__main__":
    unittest.main()
