import base64
import hashlib
import json
import re
import subprocess
import sys
import unicodedata
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "ap2-handler-safety-v0.6.json"
SPEC = ROOT / "spec" / "DACS-4-SETTLE.md"
CORE = ROOT / "spec" / "CORE.md"
PLAN = ROOT / "spec" / "CONFORMANCE-PLAN.md"
README = ROOT / "conformance" / "vectors" / "security" / "README.md"
WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"
KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
COMPACT_JWS_RE = re.compile(
    r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\Z"
)
MISSING = object()
HASH_ALGORITHMS = {
    "sha-256": hashlib.sha256,
}
JOB_ID_RE = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}\Z", re.ASCII)


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def derive_key(job_id, phase_index):
    if not isinstance(job_id, str) or JOB_ID_RE.fullmatch(job_id) is None:
        raise ValueError("jobId must satisfy JID-1")
    if type(phase_index) is not int or phase_index < 0:
        raise ValueError("phaseIndex must be a non-negative integer")
    preimage = (
        b"dacs-ap2-idem:v1:"
        + unicodedata.normalize("NFC", job_id).encode("utf-8")
        + b":"
        + str(phase_index).encode("ascii")
    )
    return hashlib.sha256(preimage).hexdigest()


def derive_transaction_id(checkout_jws, sd_alg=MISSING):
    if (
        not isinstance(checkout_jws, str)
        or not COMPACT_JWS_RE.fullmatch(checkout_jws)
    ):
        raise ValueError("checkoutJws must be an unpadded RFC 7515 compact JWS")
    algorithm = "sha-256" if sd_alg is MISSING else sd_alg
    if not isinstance(algorithm, str) or algorithm not in HASH_ALGORITHMS:
        raise ValueError("_sd_alg is unsupported")
    digest = HASH_ALGORITHMS[algorithm](checkout_jws.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


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


def evaluate_checkout_payment_admission(case):
    no_effects = {
        "reserveAp2Binding": False,
        "submitProviderPayment": False,
    }
    if not all(
        case.get(field) is True
        for field in (
            "checkoutMandatePresent",
            "checkoutMandateVerified",
            "paymentMandatePresent",
            "paymentMandateVerified",
        )
    ):
        return "fail", None, no_effects
    if evaluate_signature_policy(case) != "pass":
        return "fail", None, no_effects
    try:
        transaction_id = derive_transaction_id(
            case.get("checkoutJws"), case.get("_sd_alg", MISSING)
        )
    except ValueError:
        return "error", None, no_effects
    effects = dict(no_effects)
    if case.get("paymentTransactionId") != transaction_id:
        return "fail", transaction_id, effects
    effects["reserveAp2Binding"] = True
    effects["submitProviderPayment"] = True
    return "pass", transaction_id, effects


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
        self.assertEqual(len(cases), 7)
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

    def test_jid_gate_and_tuple_separation_are_load_bearing(self):
        base = self.cases["ap2-key-base"]
        phase = self.cases["ap2-key-phase-separation"]
        job = self.cases["ap2-key-job-separation"]
        self.assertNotEqual(base["expectedKey"], phase["expectedKey"])
        self.assertNotEqual(base["expectedKey"], job["expectedKey"])
        for name in (
            "ap2-key-noncanonical-unicode-error",
            "ap2-key-overflow-job-error",
        ):
            case = self.cases[name]
            with self.subTest(case=name), self.assertRaises(ValueError):
                derive_key(case["jobId"], case["phaseIndex"])

    def test_transaction_ids_recompute_from_exact_compact_jws_bytes(self):
        cases = [
            case for case in self.data["vectors"]
            if case["op"] == "derive-transaction-id"
        ]
        self.assertEqual(len(cases), 5)
        for case in cases:
            with self.subTest(case=case["name"]):
                if case["expected"] == "error":
                    with self.assertRaises(ValueError):
                        derive_transaction_id(
                            case["checkoutJws"], case.get("_sd_alg", MISSING)
                        )
                    self.assertNotIn("expectedTransactionId", case)
                else:
                    derived = derive_transaction_id(
                        case["checkoutJws"], case.get("_sd_alg", MISSING)
                    )
                    self.assertEqual(derived, case["expectedTransactionId"])

    def test_digest_selection_and_signature_bytes_are_load_bearing(self):
        default = self.cases["ap2-transaction-id-sha256-default"]
        explicit = self.cases["ap2-transaction-id-sha256-explicit"]
        changed = self.cases["ap2-transaction-id-signature-byte-change"]
        self.assertNotIn("_sd_alg", default)
        self.assertEqual(
            default["expectedTransactionId"],
            "rtXpY7wp4o7vknuw0ZaOpynbfydEGvpoFkFUiRFpYJU",
        )
        self.assertEqual(explicit["_sd_alg"], "sha-256")
        self.assertEqual(
            default["expectedTransactionId"], explicit["expectedTransactionId"]
        )
        default_segments = default["checkoutJws"].split(".")
        changed_segments = changed["checkoutJws"].split(".")
        self.assertEqual(default_segments[:2], changed_segments[:2])
        self.assertNotEqual(default_segments[2], changed_segments[2])
        self.assertEqual(
            changed["differentFromTransactionId"], default["expectedTransactionId"]
        )
        self.assertNotEqual(
            changed["expectedTransactionId"], changed["differentFromTransactionId"]
        )
        self.assertEqual(
            self.cases["ap2-admission-transaction-id-mismatch"]["paymentTransactionId"],
            changed["expectedTransactionId"],
        )

    def test_checkout_payment_admission_precedes_both_side_effects(self):
        cases = [
            case for case in self.data["vectors"]
            if case["op"] == "checkout-payment-admission"
        ]
        self.assertEqual(len(cases), 6)
        for case in cases:
            with self.subTest(case=case["name"]):
                verdict, derived, effects = evaluate_checkout_payment_admission(case)
                self.assertEqual(verdict, case["expected"])
                self.assertEqual(
                    effects["reserveAp2Binding"],
                    case["want"]["reserveAp2Binding"],
                )
                self.assertEqual(
                    effects["submitProviderPayment"],
                    case["want"]["submitProviderPayment"],
                )
                if "derivedTransactionId" in case["want"]:
                    self.assertEqual(derived, case["want"]["derivedTransactionId"])
                else:
                    self.assertIsNone(derived)

    def test_complete_chain_admission_composes_into_ap2_7_binding(self):
        case = self.cases["ap2-admission-complete-chain-match"]
        verdict, transaction_id, effects = evaluate_checkout_payment_admission(case)
        self.assertEqual(verdict, "pass")
        self.assertTrue(effects["reserveAp2Binding"])
        binding_case = {
            "transactionId": transaction_id,
            "jobId": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "phaseIndex": 3,
            "priorBindings": [],
        }
        self.assertEqual(
            evaluate_transaction_binding(binding_case), ("pass", "bind-new", True)
        )

    def test_new_checkout_cases_cover_positive_negative_and_boundary(self):
        classes = {
            case["caseClass"]
            for case in self.data["vectors"]
            if case["op"] in {"derive-transaction-id", "checkout-payment-admission"}
        }
        self.assertEqual(classes, {"positive", "negative", "boundary"})

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

    def test_checkout_signature_policy_uses_the_dacs_strict_profile(self):
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
        self.assertIn("DACS profiles the stricter", spec)
        self.assertIn("CheckoutMandate + PaymentMandate", spec)
        self.assertIn("base payload of the SD-JWT carrying the CheckoutMandate", spec)
        self.assertIn("MUST NOT reserve the AP2-7 binding", spec)
        self.assertIn("current Demos DAHR binding", spec)
        self.assertNotIn("AP2 v0.2's non-deterministic-signature requirement", spec)
        self.assertIn("ap2-handler-safety-v0.6.json", plan)
        self.assertIn("ap2-handler-safety-v0.6.json", readme)
        self.assertIn("generate_ap2_handler_safety_vectors.py --check", workflow)


if __name__ == "__main__":
    unittest.main()
