import hashlib
import json
import re
import subprocess
import sys
import unicodedata
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "ap2-handler-safety-v0.5.json"
SPEC = ROOT / "spec" / "DACS-4-SETTLE.md"
CORE = ROOT / "spec" / "CORE.md"
PLAN = ROOT / "spec" / "CONFORMANCE-PLAN.md"
README = ROOT / "conformance" / "vectors" / "security" / "README.md"
WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"
KEY_RE = re.compile(r"[0-9a-f]{64}\Z")


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def derive_key(job_id, phase_index):
    if not isinstance(job_id, str) or not job_id:
        raise ValueError("jobId must be a non-empty string")
    if type(phase_index) is not int or phase_index < 0:
        raise ValueError("phaseIndex must be a non-negative integer")
    preimage = (
        b"dacs-ap2-idem:v1:"
        + unicodedata.normalize("NFC", job_id).encode("utf-8")
        + b":"
        + str(phase_index).encode("ascii")
    )
    return hashlib.sha256(preimage).hexdigest()


def evaluate_transaction_binding(case):
    prior = case["priorBindings"]
    if not isinstance(prior, list):
        return "error", "refuse-conflict", False
    matches = [entry for entry in prior if entry.get("transactionId") == case["transactionId"]]
    if len(matches) > 1:
        return "error", "refuse-conflict", False
    if not matches:
        return "pass", "bind-new", True
    bound = matches[0]
    same_tuple = (
        bound.get("jobId") == case["jobId"]
        and bound.get("phaseIndex") == case["phaseIndex"]
    )
    if not same_tuple:
        return "fail", "reject-replay", False
    if bound.get("state") == "settled":
        return "pass", "resume-settlement", False
    if bound.get("state") == "in-flight":
        return "pass", "resume-existing", False
    return "error", "refuse-conflict", False


def evaluate_signature_policy(case):
    return (
        "pass"
        if case.get("signatureGeneration") == "non-deterministic"
        and case.get("algorithm") != "Ed25519"
        else "fail"
    )


def evaluate_registration(case):
    eligible = (
        case.get("createCredential") is True
        and case.get("statusOnlyCredential") is True
        and case.get("credentialsDistinct") is True
        and case.get("createCredentialRelayed") is False
    )
    return "pass" if eligible else "fail"


class Ap2HandlerSafetyVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {case["name"]: case for case in cls.data["vectors"]}

    def test_vector_hash_count_and_names_are_exact(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(len({case["name"] for case in vectors}), len(vectors))
        self.assertEqual(
            self.data["hash"], hashlib.sha256(canonical_json(vectors)).hexdigest()
        )

    def test_idempotency_keys_recompute_from_raw_inputs(self):
        cases = [case for case in self.data["vectors"] if case["op"] == "derive-idempotency-key"]
        self.assertEqual(len(cases), 6)
        for case in cases:
            with self.subTest(case=case["name"]):
                if case["expected"] == "error":
                    with self.assertRaises(ValueError):
                        derive_key(case["jobId"], case["phaseIndex"])
                    self.assertNotIn("expectedKey", case)
                else:
                    derived = derive_key(case["jobId"], case["phaseIndex"])
                    self.assertRegex(derived, KEY_RE)
                    self.assertEqual(derived, case["expectedKey"])

    def test_nfc_and_tuple_separation_are_load_bearing(self):
        base = self.cases["ap2-key-base"]
        phase = self.cases["ap2-key-phase-separation"]
        job = self.cases["ap2-key-job-separation"]
        nfc = self.cases["ap2-key-nfc-normalization"]
        self.assertNotEqual(base["expectedKey"], phase["expectedKey"])
        self.assertNotEqual(base["expectedKey"], job["expectedKey"])
        self.assertNotEqual(nfc["jobId"], nfc["normalizedJobId"])
        self.assertEqual(
            derive_key(nfc["jobId"], nfc["phaseIndex"]),
            derive_key(nfc["normalizedJobId"], nfc["phaseIndex"]),
        )

    def test_transaction_binding_executes_retry_and_replay_rules(self):
        cases = [case for case in self.data["vectors"] if case["op"] == "transaction-binding"]
        self.assertEqual(len(cases), 6)
        for case in cases:
            with self.subTest(case=case["name"]):
                verdict, action, submit_new = evaluate_transaction_binding(case)
                self.assertEqual(verdict, case["expected"])
                self.assertEqual(action, case["want"]["action"])
                self.assertEqual(submit_new, case["want"]["submitNewPayment"])

    def test_exact_tuple_retries_never_submit_a_second_payment(self):
        for name in (
            "ap2-same-tuple-inflight-resumes",
            "ap2-same-tuple-settled-resumes-evidence",
        ):
            case = self.cases[name]
            verdict, action, submit_new = evaluate_transaction_binding(case)
            self.assertEqual(verdict, "pass")
            self.assertTrue(action.startswith("resume-"))
            self.assertFalse(submit_new)

    def test_checkout_signature_policy_uses_the_upstream_property(self):
        cases = [case for case in self.data["vectors"] if case["op"] == "checkout-signature-policy"]
        self.assertEqual(len(cases), 3)
        for case in cases:
            with self.subTest(case=case["name"]):
                self.assertEqual(evaluate_signature_policy(case), case["expected"])

    def test_registration_requires_split_least_privilege_credentials(self):
        cases = [case for case in self.data["vectors"] if case["op"] == "registration-eligibility"]
        self.assertEqual(len(cases), 4)
        for case in cases:
            with self.subTest(case=case["name"]):
                self.assertEqual(evaluate_registration(case), case["expected"])

    def test_generator_check_is_enforced(self):
        result = subprocess.run(
            [sys.executable, "scripts/generate_ap2_handler_safety_vectors.py", "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_spec_registry_plan_readme_and_ci_are_linked(self):
        spec = SPEC.read_text(encoding="utf-8")
        core = CORE.read_text(encoding="utf-8")
        plan = PLAN.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('"dacs-ap2-idem:v1:"', spec)
        self.assertIn('`dacs-ap2-idem:v1:`', core)
        self.assertIn("same `(jobId, phaseIndex)`", spec)
        self.assertIn("non-deterministic-signature requirement", spec)
        self.assertIn("ap2-handler-safety-v0.5.json", plan)
        self.assertIn("ap2-handler-safety-v0.5.json", readme)
        self.assertIn("generate_ap2_handler_safety_vectors.py --check", workflow)


if __name__ == "__main__":
    unittest.main()
