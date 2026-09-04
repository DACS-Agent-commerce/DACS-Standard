import hashlib
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "legacy-agreement-admission-v0.8.json"
)
SPEC3 = ROOT / "spec" / "DACS-3-NEGOTIATE.md"
SPEC4 = ROOT / "spec" / "DACS-4-SETTLE.md"
SPEC5 = ROOT / "spec" / "DACS-5-VERIFY.md"
CORE = ROOT / "spec" / "CORE.md"
PLAN = ROOT / "spec" / "CONFORMANCE-PLAN.md"
README = ROOT / "conformance" / "vectors" / "security" / "README.md"
WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"
POSITION_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
CHECKPOINT_DOMAIN = "dacs-legacy-agreement-checkpoint:v1:"


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def before_checkpoint(record, checkpoint_position):
    raw = record.get("position")
    if not isinstance(raw, str) or not POSITION_RE.fullmatch(raw):
        return "error"
    position = int(raw)
    if position < checkpoint_position:
        return "pass"
    if position > checkpoint_position:
        return "fail"
    strict = record.get("strictlyBeforeAtSamePosition")
    if strict is True:
        return "pass"
    if strict is False:
        return "fail"
    return "indeterminate"


def validate_record(record, binding_field):
    if record.get("shape") != "valid":
        return "error"
    if record.get(binding_field) is not True or record.get("signatureValid") is not True:
        return "fail"
    if record.get("receiptState") != "finalized":
        return "indeterminate"
    return "pass"


def evaluate(value):
    """Independent model of the LAA/CA-10 fail-closed ordering."""
    agreement = value["agreement"]
    if agreement.get("shape") != "valid":
        return "error"
    if agreement.get("partySignaturesValid") is not True:
        return "fail"
    artifact = agreement.get("artifact")
    if artifact not in {"legacy", "payee-bound"}:
        return "error"
    if artifact == "payee-bound":
        return "pass" if agreement.get("pbVerified") is True else "fail"
    if value.get("pipelineHasPayment") is False:
        return "pass"

    checkpoint = value["checkpoint"]
    resolution = checkpoint.get("resolution")
    if resolution == "absent":
        return "pass" if checkpoint.get("authenticatedAbsence") is True else "indeterminate"
    if resolution in {"unavailable", "conflicting", "reorged", "pruned"}:
        return "indeterminate"
    if resolution != "verified":
        return "error"
    if checkpoint.get("shape") != "valid" or checkpoint.get("discriminator") != "legacyAgreementCheckpointVersion:1":
        return "error"
    if any(checkpoint.get(field) is not True for field in (
        "signatureValid", "stewardAuthorized", "addressMatches", "policyMatches"
    )):
        return "fail"
    if checkpoint.get("signatureDomain") != CHECKPOINT_DOMAIN:
        return "fail"
    if checkpoint.get("receiptState") != "finalized":
        return "indeterminate"
    raw_checkpoint_position = checkpoint.get("position")
    if not isinstance(raw_checkpoint_position, str) or not POSITION_RE.fullmatch(raw_checkpoint_position):
        return "error"
    checkpoint_position = int(raw_checkpoint_position)

    if value.get("operation") in {"authorize-payment", "commit-pay-bearing"}:
        return "fail"
    if value.get("operation") != "historical-audit":
        return "error"

    commitment = value["commitment"]
    settlement = value["settlementEvidence"]
    for record in (commitment, settlement):
        if record.get("resolution") in {"unavailable", "absent", "pruned", "reorged"}:
            return "indeterminate"
        if record.get("resolution") != "verified":
            return "error"
    result = validate_record(commitment, "agreementHashMatches")
    if result != "pass":
        return result
    result = validate_record(settlement, "agreementBindingMatches")
    if result != "pass":
        return result

    results = [
        before_checkpoint(commitment, checkpoint_position),
        before_checkpoint(settlement, checkpoint_position),
    ]
    if "error" in results:
        return "error"
    if "fail" in results:
        return "fail"
    if "indeterminate" in results:
        return "indeterminate"
    return "pass"


class LegacyAgreementAdmissionVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {case["name"]: case for case in cls.data["vectors"]}

    def test_hash_count_and_names_are_exact(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], 34)
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(len({case["name"] for case in vectors}), len(vectors))
        self.assertEqual(
            self.data["hash"], hashlib.sha256(canonical_json(vectors)).hexdigest()
        )

    def test_every_vector_executes_to_declared_result_and_effects(self):
        for case in self.data["vectors"]:
            with self.subTest(case=case["name"]):
                verdict = evaluate(case["input"])
                self.assertEqual(verdict, case["expected"])
                want = case["want"]
                self.assertEqual(want["paymentSideEffects"], want["currentPaymentEligible"])
                if verdict != "pass":
                    self.assertFalse(want["paymentSideEffects"])
                self.assertEqual(
                    want["dacs5Admission"],
                    {"pass": "continue", "fail": "rejected", "error": "rejected"}.get(
                        verdict, verdict
                    ),
                )
                if case["input"]["operation"] == "historical-audit":
                    self.assertEqual(want["historicalAuditEligible"], verdict == "pass")

    def test_acceptance_criteria_and_precedence_are_covered(self):
        required = {
            "laa-current-payee-bound-success",
            "laa-fresh-legacy-after-checkpoint",
            "laa-backdated-generated-at",
            "laa-authentic-historical-settlement",
            "laa-missing-commitment-era-proof",
            "laa-no-in-flight-transition",
            "laa-same-position-unorderable",
            "laa-deterministic-mismatch-precedes-outage",
            "laa-ca10-postactivation-legacy-commit",
        }
        self.assertTrue(required.issubset(self.cases))
        case = self.cases["laa-deterministic-mismatch-precedes-outage"]
        self.assertEqual(evaluate(case["input"]), "fail")
        self.assertTrue(
            self.cases["laa-fresh-legacy-after-checkpoint"]["want"]
            ["legacyBytesCryptographicallyInspectable"]
        )

    def test_generator_check_is_enforced(self):
        result = subprocess.run(
            [sys.executable, "scripts/generate_legacy_agreement_admission_vectors.py", "--check"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_normative_surfaces_registry_plan_readme_and_ci_are_linked(self):
        spec3 = SPEC3.read_text(encoding="utf-8")
        spec4 = SPEC4.read_text(encoding="utf-8")
        spec5 = SPEC5.read_text(encoding="utf-8")
        core = CORE.read_text(encoding="utf-8")
        plan = PLAN.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for rule in range(1, 8):
            self.assertIn(f"(LAA-{rule})", spec4)
        self.assertIn("(CA-10)", spec3)
        self.assertIn("LAA-1..LAA-7", spec5)
        self.assertIn("LAA `fail` or `error` yields RSV `rejected`", spec5)
        self.assertIn("inFlightTransition: \"none\"", spec4)
        self.assertIn("generatedAt", spec4)
        self.assertIn('"dacs-legacy-agreement-checkpoint:v1:"', core)
        self.assertIn(VECTORS.name, plan)
        self.assertIn(VECTORS.name, readme)
        self.assertIn("generate_legacy_agreement_admission_vectors.py --check", workflow)


if __name__ == "__main__":
    unittest.main()
