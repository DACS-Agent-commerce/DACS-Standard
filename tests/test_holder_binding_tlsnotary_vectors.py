import hashlib
import json
import re
import unicodedata
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "holder-binding-tlsnotary-v0.1.json"
)
SPEC = ROOT / "spec" / "DACS-2-VET.md"


def session_nonce(bundle):
    """The §6.3.2 disjunction: SIWD Nonce for a siwd bundle, else top level."""
    if bundle.get("presentation") == "siwd":
        return (bundle.get("siwd") or {}).get("nonce")
    return bundle.get("sessionNonce")


def subject_verdict(identifier, subject):
    """Step 5: None means the segments disclose no subject value."""
    if subject is None:
        return "indeterminate"
    same = unicodedata.normalize("NFC", subject) == unicodedata.normalize(
        "NFC", identifier
    )
    return "pass" if same else "fail"


def binding_verdict(vector):
    """Step 6: holder proof over the current nonce and this proof's commitment."""
    holder = vector.get("holderProof")
    nonce = session_nonce(vector["bundle"])
    if holder is None or nonce is None:
        return "fail"
    challenge = holder["challenge"]
    bound = (
        holder["signatureVerifies"] is True
        and challenge["sessionNonce"] == nonce
        and challenge["proofCommitment"] == vector["proof"]["commitment"]
    )
    return "pass" if bound else "fail"


def evaluate(vector):
    subject = subject_verdict(vector["identifier"], vector["proof"]["subject"])
    if subject != "pass":
        return subject
    return binding_verdict(vector)


class HolderBindingTLSNotaryVectorTests(unittest.TestCase):
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

    def test_every_vector_verdict_matches_the_step_predicates(self):
        for name, vector in self.vectors.items():
            with self.subTest(name):
                self.assertEqual(evaluate(vector), vector["expected"])

    def test_required_cases_are_present_with_their_verdicts(self):
        required = {
            "subject-matches-binding-current-nonce": "pass",
            "subject-differs-from-claim-identifier": "fail",
            "binding-over-another-session-nonce": "fail",
            "binding-absent": "fail",
            "siwd-binding-over-siwd-nonce": "pass",
            "siwd-binding-over-top-level-nonce": "fail",
        }
        for name, expected in required.items():
            with self.subTest(name):
                self.assertEqual(self.vectors[name]["expected"], expected)

    def test_siwd_and_top_level_nonce_choice(self):
        siwd = self.vectors["siwd-binding-over-siwd-nonce"]["bundle"]
        self.assertIsNone(siwd.get("sessionNonce"))
        self.assertEqual(session_nonce(siwd), siwd["siwd"]["nonce"])

        both = self.vectors["siwd-binding-over-top-level-nonce"]["bundle"]
        self.assertNotEqual(both["sessionNonce"], both["siwd"]["nonce"])
        self.assertEqual(session_nonce(both), both["siwd"]["nonce"])

        per_claim = self.vectors["per-claim-ignores-siwd-field"]["bundle"]
        self.assertEqual(session_nonce(per_claim), per_claim["sessionNonce"])

    def test_spec_states_the_steps_the_predicates_model(self):
        text = SPEC.read_text(encoding="utf-8")
        start = text.index("#### 7.3.3 tlsnotary")
        section = text[start:text.index("#### 7.3.4 zktls")]
        for label in ("**Subject match**", "**Session binding**", "*Outcome.*"):
            self.assertIn(label, section)
        self.assertIn("holderProof: TLSNotaryHolderProof", section)
        self.assertRegex(section, r"CORE §B\.8 \(SN-1\.\.4\)")
        self.assertRegex(section, r"SIWD message `Nonce`")
        steps = re.findall(r"^\d+\. ", section, flags=re.MULTILINE)
        self.assertEqual(len(steps), 8)


if __name__ == "__main__":
    unittest.main()
