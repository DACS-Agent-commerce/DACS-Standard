import copy
import hashlib
import json
import re
import unicodedata
import unittest
from encodings.idna import nameprep
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "tlsnotary-session-subject-binding-v0.1.json"
)
SPEC = ROOT / "spec" / "DACS-2-VET.md"


class OracleRefusal(ValueError):
    """The reduced oracle cannot check this label faithfully to IDNA2008."""


# Characters IDNA2003 maps or splits differently from IDNA2008: sharp s, final
# sigma, ZWNJ, ZWJ, and the ideographic full stop (a label separator only in
# IDNA2003).
IDNA_DIVERGENT = frozenset("ßς‌‍。")


def refuse_unfaithful_label(text):
    """Raise OracleRefusal for a non-ASCII character the oracle cannot check.

    A character passes only if it is not in IDNA_DIVERGENT and IDNA2003
    nameprep leaves it as its own lowercase form; a character nameprep maps
    to anything else (case folding, NFKC, deletion) or prohibits is refused.
    """
    for char in text:
        if char.isascii():
            continue
        try:
            mapped = nameprep(char)
        except UnicodeError as error:
            raise OracleRefusal(f"nameprep rejects {char!r}") from error
        if char in IDNA_DIVERGENT or mapped != char or char != char.lower():
            raise OracleRefusal(f"IDNA2003 and IDNA2008 may differ on {char!r}")


def session_nonce(bundle):
    """The §6.3.2 disjunction: SIWD Nonce for a siwd bundle, else top level."""
    if bundle["presentation"] == "siwd":
        return (bundle.get("siwd") or {}).get("nonce")
    return bundle.get("sessionNonce")


def canonical(scheme, identifier):
    """CF-2(b): NFC, then the scheme's identifier rule; None if it cannot apply.

    For domain this is DCR-1 (lowercase A-label). The standard library's idna
    codec (IDNA2003 ToASCII) stands in for IDNA2008 so no dependency is needed.
    It is only faithful where the two agree, so refuse_unfaithful_label raises
    OracleRefusal for any character where they may differ.
    """
    text = unicodedata.normalize("NFC", identifier)
    if scheme != "domain":
        return text
    refuse_unfaithful_label(text)
    try:
        return text.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def stored_proof_ok(vector):
    """Step 4, cci-tlsn only: the supplied proof equals the proof stored for H."""
    if vector["scheme"] != "cci-tlsn":
        return True
    stored = vector.get("storedEntry")
    return stored is not None and stored["proof"] == vector["proof"]["body"]


def binding_ok(vector):
    """Step 4: every claim entry in this session's bundle carries the commitment."""
    if not stored_proof_ok(vector):
        return False
    scheme, identifier = vector["scheme"], vector["identifier"]
    wanted = canonical(scheme, identifier)
    found = False
    for bundle in vector["bundles"]:
        if session_nonce(bundle) != vector["issuedNonce"]:
            continue
        for entry in bundle["claims"]:
            if canonical(scheme, entry["identifier"]) != wanted:
                continue
            value = entry.get("tlsnotaryProofCommitment")
            if not isinstance(value, str) or value != vector["proof"]["commitment"]:
                return False
            found = True
    return found


def subject_ok(vector):
    """Step 6: only when the recipe declares a subject dataMap entry."""
    if "subject" not in vector["recipe"]["dataMap"]:
        return True
    subject = vector["proof"]["subject"]
    scheme = vector["scheme"]
    if not isinstance(subject, str):
        return False
    claimed = vector["identifier"]
    if scheme == "cci-tlsn":
        claimed = vector["storedEntry"]["userId"]
    disclosed = canonical(scheme, subject)
    return disclosed is not None and disclosed == canonical(scheme, claimed)


def evaluate(vector):
    """First failing step decides; returns (verdict, failed step, establishes)."""
    if not binding_ok(vector):
        return "fail", "session-binding", None
    if not subject_ok(vector):
        return "fail", "subject-match", None
    if "subject" in vector["recipe"]["dataMap"]:
        return "pass", None, "proof-subject-matches-claim"
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

    def test_u_label_subjects_are_already_lowercase(self):
        # IDNA2003 lowercases before ToASCII; strict IDNA2008 rejects an
        # uppercase letter. Lowercase subjects make both codecs agree.
        for name, vector in self.vectors.items():
            subject = vector["proof"]["subject"]
            if not isinstance(subject, str) or subject.isascii():
                continue
            with self.subTest(name):
                self.assertEqual(subject, subject.lower())

    def test_oracle_refuses_labels_it_cannot_check_faithfully(self):
        # IDNA2003 maps these differently from IDNA2008 (DCR-1): "ß.example"
        # becomes "ss.example" instead of "xn--zca.example". Raising keeps the
        # oracle from passing "ss.example" against "ß.example".
        for subject in ("ß.example", "ς.example", "a‌b.example",
                        "a‍b.example", "a。b.example"):
            with self.subTest(subject):
                with self.assertRaises(OracleRefusal):
                    canonical("domain", subject)
                vector = copy.deepcopy(self.vectors["subject-declared-and-matches"])
                vector["scheme"] = "domain"
                vector["identifier"] = "ss.example"
                vector["proof"]["subject"] = subject
                for bundle in vector["bundles"]:
                    for entry in bundle["claims"]:
                        entry["identifier"] = "ss.example"
                with self.assertRaises(OracleRefusal):
                    evaluate(vector)

    def test_every_u_label_subject_in_the_corpus_is_accepted_by_the_oracle(self):
        checked = []
        for name, vector in self.vectors.items():
            subject = vector["proof"]["subject"]
            if (vector["scheme"] != "domain" or not isinstance(subject, str)
                    or subject.isascii()):
                continue
            with self.subTest(name):
                canonical("domain", subject)
                checked.append(name)
        self.assertTrue(checked)

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
            "subject-matches-after-domain-a-label": ("pass", None),
            "subject-not-canonicalisable-under-scheme": ("fail", "subject-match"),
            "commitment-not-a-string": ("fail", "session-binding"),
            "commitment-differs-in-hex-case": ("fail", "session-binding"),
            "duplicate-entries-one-lacks-commitment": ("fail", "session-binding"),
            "cci-tlsn-stored-proof-and-user-id-subject": ("pass", None),
            "cci-tlsn-other-valid-proof-is-not-the-stored-proof": (
                "fail", "session-binding"),
            "cci-tlsn-stored-proof-subject-differs-from-user-id": (
                "fail", "subject-match"),
            "cci-tlsn-subject-equal-to-h-text-is-not-user-id": (
                "fail", "subject-match"),
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
                    "proof-subject-matches-claim"
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
        self.assertIn("a bundle for this session carried its commitment", section)
        self.assertIn("lowercase hex", section)
        self.assertIn("`subject` entry", section)
        self.assertIn("requires `proof` to equal the proof stored", section)
        self.assertIn("the `userId` of the stored entry resolved in step 4", section)
        self.assertIn("equals the claimed identifier", section)
        self.assertIn("does not show that the presenter controls the account", section)
        self.assertIn("Neither result establishes account control", section)


if __name__ == "__main__":
    unittest.main()
