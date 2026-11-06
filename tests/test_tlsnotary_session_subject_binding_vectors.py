import hashlib
import json
import re
import unicodedata
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "tlsnotary-session-subject-binding-v0.1.json"
)
SPEC = ROOT / "spec" / "DACS-2-VET.md"


def session_nonce(bundle):
    """The §6.3.2 disjunction: SIWD Nonce for a siwd bundle, else top level."""
    if bundle["presentation"] == "siwd":
        return (bundle.get("siwd") or {}).get("nonce")
    return bundle.get("sessionNonce")


def canonical(scheme, identifier):
    """CF-2(b): NFC, then the scheme's identifier rule (domain: lowercase)."""
    text = unicodedata.normalize("NFC", identifier)
    return text.lower() if scheme == "domain" else text


def binding_ok(vector):
    """Step 4: the commitment is in this session's bundle entry for the claim."""
    scheme, identifier = vector["scheme"], vector["identifier"]
    for bundle in vector["bundles"]:
        if session_nonce(bundle) != vector["issuedNonce"]:
            continue
        for entry in bundle["claims"]:
            if canonical(scheme, entry["identifier"]) != canonical(
                scheme, identifier
            ):
                continue
            if entry.get("tlsnotaryProofCommitment") == vector["proof"]["commitment"]:
                return True
    return False


def subject_ok(vector):
    """Step 6: only when the recipe declares a subject dataMap entry."""
    if "subject" not in vector["recipe"]["dataMap"]:
        return True
    subject = vector["proof"]["subject"]
    scheme = vector["scheme"]
    return subject is not None and canonical(scheme, subject) == canonical(
        scheme, vector["identifier"]
    )


def evaluate(vector):
    """First failing step decides; returns (verdict, failed step, establishes)."""
    if not binding_ok(vector):
        return "fail", "session-binding", None
    if not subject_ok(vector):
        return "fail", "subject-match", None
    if "subject" in vector["recipe"]["dataMap"]:
        return "pass", None, "account-belongs-to-presenter"
    return "pass", None, "proof-presented-in-session"


class TLSNotarySessionSubjectBindingVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.vectors = {v["name"]: v for v in cls.document["vectors"]}

    def test_set_metadata_is_self_consistent(self):
        document = self.document
        self.assertEqual(document["set"], VECTORS.stem)
        self.assertEqual(document["count"], len(document["vectors"]))
        self.assertEqual(len(self.vectors), len(document["vectors"]))
        digest = hashlib.sha256(
            json.dumps(
                document["vectors"], separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(document["hash"], digest)

    def test_every_vector_matches_the_step_predicates(self):
        for name, vector in self.vectors.items():
            with self.subTest(name):
                self.assertEqual(
                    evaluate(vector),
                    (vector["expected"], vector["failedStep"], vector["establishes"]),
                )

    def test_required_cases_are_present_with_their_results(self):
        required = {
            "commitment-in-session-bundle-entry": ("pass", None),
            "commitment-missing-from-bundle-entry": ("fail", "session-binding"),
            "commitment-only-in-another-session-bundle": ("fail", "session-binding"),
            "siwd-bundle-uses-siwd-nonce": ("pass", None),
            "siwd-bundle-top-level-nonce-is-not-this-session": (
                "fail", "session-binding"),
            "subject-declared-and-matches": ("pass", None),
            "subject-declared-and-differs": ("fail", "subject-match"),
            "no-subject-entry-pass-is-session-only": ("pass", None),
            "bad-binding-and-mismatching-subject": ("fail", "session-binding"),
        }
        for name, (verdict, step) in required.items():
            with self.subTest(name):
                self.assertEqual(
                    (self.vectors[name]["expected"], self.vectors[name]["failedStep"]),
                    (verdict, step),
                )

    def test_pass_without_subject_entry_is_limited(self):
        for name, vector in self.vectors.items():
            if vector["expected"] != "pass":
                continue
            with self.subTest(name):
                declared = "subject" in vector["recipe"]["dataMap"]
                self.assertEqual(
                    vector["establishes"],
                    "account-belongs-to-presenter"
                    if declared else "proof-presented-in-session",
                )

    def test_bad_binding_is_decided_before_the_subject(self):
        vector = self.vectors["bad-binding-and-mismatching-subject"]
        self.assertFalse(binding_ok(vector))
        self.assertFalse(subject_ok(vector))
        self.assertEqual(evaluate(vector)[1], "session-binding")

    def test_siwd_and_top_level_nonce_choice(self):
        siwd = self.vectors["siwd-bundle-uses-siwd-nonce"]["bundles"][0]
        self.assertNotIn("sessionNonce", siwd)
        self.assertEqual(session_nonce(siwd), siwd["siwd"]["nonce"])

        both = self.vectors["siwd-bundle-top-level-nonce-is-not-this-session"]
        bundle = both["bundles"][0]
        self.assertEqual(bundle["sessionNonce"], both["issuedNonce"])
        self.assertNotEqual(session_nonce(bundle), both["issuedNonce"])

        per_claim = self.vectors["per-claim-bundle-ignores-siwd-field"]
        bundle = per_claim["bundles"][0]
        self.assertEqual(session_nonce(bundle), per_claim["issuedNonce"])
        self.assertNotEqual(bundle["siwd"]["nonce"], per_claim["issuedNonce"])

    def test_spec_states_the_steps_in_order(self):
        text = SPEC.read_text(encoding="utf-8")
        start = text.index("#### 7.3.3 tlsnotary")
        section = text[start:text.index("#### 7.3.4 zktls")]
        steps = re.findall(r"^\d+\. \*\*([^*]+)\*\*", section, flags=re.MULTILINE)
        self.assertEqual(
            steps,
            ["Validate the proof", "Verify the notary signature", "Session template",
             "Session binding", "Extract", "Subject match", "Anchor", "Return"],
        )
        self.assertIn("the first failing step decides the verdict", section)
        self.assertIn("metadata.tlsnotaryProofCommitment", section)
        self.assertNotIn("holderProof", section)
        self.assertIn("a valid proof was presented in this session", section)
        self.assertIn("`subject` entry", section)


if __name__ == "__main__":
    unittest.main()
