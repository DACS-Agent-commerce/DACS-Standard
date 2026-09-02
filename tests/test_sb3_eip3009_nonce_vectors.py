import hashlib
import json
import re
import unicodedata
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "sb3-eip3009-nonce-v0.1.json"
SPEC = ROOT / "spec" / "DACS-4-SETTLE.md"
README = ROOT / "conformance" / "vectors" / "security" / "README.md"

NONCE_RE = re.compile(r"0x[0-9a-f]{64}\Z")
ULID_RE = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}\Z", re.ASCII)


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def derive_nonce(job_id, phase_index):
    if not isinstance(job_id, str) or ULID_RE.fullmatch(job_id) is None:
        raise ValueError("jobId must satisfy JID-1")
    if type(phase_index) is not int or phase_index < 0:
        raise ValueError("phaseIndex must be a non-negative integer")
    preimage = (
        b"dacs-sb3:v1:"
        + unicodedata.normalize("NFC", job_id).encode("utf-8")
        + b":"
        + str(phase_index).encode("ascii")
    )
    return "0x" + hashlib.sha256(preimage).hexdigest()


def derive_legacy_nonce(job_id, phase_index):
    """Frozen pre-JID-1 derivation-only fixture path; never live authority."""
    if not isinstance(job_id, str):
        raise ValueError("jobId must be a string")
    if type(phase_index) is not int or phase_index < 0:
        raise ValueError("phaseIndex must be a non-negative integer")
    preimage = (
        b"dacs-sb3:v1:"
        + unicodedata.normalize("NFC", job_id).encode("utf-8")
        + b":"
        + str(phase_index).encode("ascii")
    )
    return "0x" + hashlib.sha256(preimage).hexdigest()


class Sb3Eip3009NonceVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {case["name"]: case for case in cls.data["vectors"]}

    def test_vector_hash_and_count_are_byte_exact(self):
        self.assertEqual(self.data["count"], len(self.data["vectors"]))
        self.assertEqual(
            self.data["hash"],
            hashlib.sha256(canonical_json(self.data["vectors"])).hexdigest(),
        )

    def test_every_pinned_nonce_recomputes_from_raw_inputs(self):
        pinned = [case for case in self.data["vectors"] if "expectedNonce" in case]
        self.assertEqual(len(pinned), 10)
        for case in pinned:
            with self.subTest(case=case["name"]):
                expected = case["expectedNonce"]
                self.assertRegex(expected, NONCE_RE)
                derive = (
                    derive_nonce
                    if case["validationScope"] == "full-input"
                    else derive_legacy_nonce
                )
                self.assertEqual(derive(case["jobId"], case["phaseIndex"]), expected)
                if "derivedNonce" in case:
                    self.assertEqual(case["derivedNonce"], expected)
                if "derivedNonce" in case["want"]:
                    self.assertEqual(case["want"]["derivedNonce"], expected)

    def test_binding_cases_compare_presented_and_expected_nonce(self):
        for case in self.data["vectors"]:
            if case["op"] != "verify-binding" or "expectedNonce" not in case:
                continue
            with self.subTest(case=case["name"]):
                matches = case["presentedNonce"] == case["expectedNonce"]
                want_matches = case["want"]["binding"] == "present-and-matches"
                self.assertEqual(matches, want_matches)
                self.assertEqual(case["expected"] == "pass", want_matches)
                if not matches:
                    self.assertFalse(case["want"]["fallback"])

    def test_malformed_phase_inputs_refuse_before_derivation(self):
        for name in ["negative-phase-index-error", "leading-zero-phase-index-error"]:
            with self.subTest(case=name):
                case = self.cases[name]
                self.assertNotIn("expectedNonce", case)
                with self.assertRaises(ValueError):
                    derive_legacy_nonce(case["jobId"], case["phaseIndex"])
                self.assertEqual(case["expected"], "error")
                self.assertEqual(case["want"]["binding"], "malformed-input")

    def test_malformed_nonce_text_refuses_before_binding_comparison(self):
        for name in ["short-nonce-error", "missing-hex-prefix-error"]:
            with self.subTest(case=name):
                case = self.cases[name]
                self.assertNotRegex(case["presentedNonce"], NONCE_RE)
                self.assertNotIn("expectedNonce", case)
                self.assertEqual(case["expected"], "error")
                self.assertEqual(case["want"]["binding"], "malformed")

    def test_nfc_equivalence_is_archival_only_and_current_path_refuses(self):
        case = self.cases["job-id-nfc-normalized"]
        decomposed = case["jobId"]
        composed = unicodedata.normalize("NFC", decomposed)
        self.assertNotEqual(decomposed, composed)
        self.assertEqual(composed, case["want"]["normalizedJobId"])
        self.assertEqual(
            derive_legacy_nonce(decomposed, case["phaseIndex"]),
            derive_legacy_nonce(composed, case["phaseIndex"]),
        )
        with self.assertRaises(ValueError):
            derive_nonce(decomposed, case["phaseIndex"])
        with self.assertRaises(ValueError):
            derive_nonce(composed, case["phaseIndex"])

    def test_job_and_phase_separation_are_pinned(self):
        live = self.cases["reported-live-vector"]["expectedNonce"]
        self.assertNotEqual(live, self.cases["phase-index-changes-nonce"]["expectedNonce"])
        self.assertNotEqual(live, self.cases["job-id-changes-nonce"]["expectedNonce"])

    def test_full_input_case_uses_a_valid_ulid(self):
        full_input = [
            case
            for case in self.data["vectors"]
            if case["validationScope"] == "full-input"
        ]
        self.assertEqual(len(full_input), 1)
        case = full_input[0]
        self.assertRegex(case["jobId"], ULID_RE)
        self.assertEqual(case["expected"], "pass")
        for other in self.data["vectors"]:
            if other is not case:
                self.assertEqual(other["validationScope"], "derivation-only")

    def test_retry_cases_never_generate_a_fresh_nonce(self):
        retries = [case for case in self.data["vectors"] if case["op"] == "retry"]
        self.assertEqual(len(retries), 3)
        for case in retries:
            with self.subTest(case=case["name"]):
                self.assertEqual(case["derivedNonce"], case["expectedNonce"])
                self.assertFalse(case["want"]["mustGenerateFreshNonce"])

    def test_spec_and_readme_link_the_executable_check(self):
        spec = SPEC.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        self.assertIn('"dacs-sb3:v1:"', spec)
        self.assertIn("UTF8(NFC(jobId))", spec)
        self.assertIn("JID-1", spec)
        self.assertIn("tests.test_sb3_eip3009_nonce_vectors", readme)
        self.assertIn("`expectedNonce`", readme)
        self.assertIn("`validationScope`", readme)


if __name__ == "__main__":
    unittest.main()
