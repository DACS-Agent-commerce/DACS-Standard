import copy
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


class OracleRefusal(ValueError):
    """The reduced oracle cannot check this label faithfully to IDNA2008."""


# Characters IDNA2003 maps or splits differently from IDNA2008: sharp s, final
# sigma, ZWNJ, ZWJ, and the ideographic full stop (a label separator only in
# IDNA2003).
IDNA_DIVERGENT = frozenset("ßς\u200c\u200d。")

# The only non-ASCII characters (after NFC) the oracle accepts. Each is a
# lowercase letter that IDNA2008 permits (PVALID) and that IDNA2003 leaves
# unchanged, so both give the same A-label. Anything else is refused rather
# than guessed: IDNA2003 accepts symbols such as U+1F600 that IDNA2008
# disallows.
ORACLE_SUPPORTED = frozenset("éü")

# The largest integer a safe-integer userId can hold (2**53 - 1).
SAFE_INTEGER_MAX = 2**53 - 1


def refuse_unfaithful_label(text):
    """Raise OracleRefusal for a non-ASCII character the oracle cannot check.

    A non-ASCII character passes only if it is in ORACLE_SUPPORTED; every
    other one (IDNA_DIVERGENT included) is refused.
    """
    for char in text:
        if char.isascii() or char in ORACLE_SUPPORTED:
            continue
        raise OracleRefusal(f"the reduced oracle does not check {char!r}")


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


def user_id_text(user_id):
    """Step 6, cci-tlsn: the stored userId as text; None if it has no text form.

    A string is itself. A safe integer is written in base 10 with no sign,
    leading zeros or exponent.
    """
    if isinstance(user_id, str):
        return user_id
    if isinstance(user_id, int) and not isinstance(user_id, bool):
        if 0 <= user_id <= SAFE_INTEGER_MAX:
            return str(user_id)
    return None


def subject_ok(vector):
    """Step 6: only when the recipe declares a subject dataMap entry."""
    if "subject" not in vector["recipe"]["dataMap"]:
        return True
    subject = vector["proof"]["subject"]
    scheme = vector["scheme"]
    if not isinstance(subject, str):
        return False
    if scheme == "cci-tlsn":
        # The 64-hex identifier rule applies to H, not to userId: compare text.
        user_id = user_id_text(vector["storedEntry"]["userId"])
        return (user_id is not None
                and unicodedata.normalize("NFC", subject)
                == unicodedata.normalize("NFC", user_id))
    disclosed = canonical(scheme, subject)
    return disclosed is not None and disclosed == canonical(scheme, vector["identifier"])


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

    def test_cci_tlsn_identifiers_follow_the_dacs1_rule(self):
        # DACS-1 §6.3.1: a cci-tlsn identifier is a 64 lowercase hex proof hash.
        rule = re.compile(r"\A[0-9a-f]{64}\Z")
        tlsn = [v for v in self.document["vectors"] if v["scheme"] == "cci-tlsn"]
        self.assertTrue(tlsn)
        for vector in tlsn:
            with self.subTest(vector=vector["name"]):
                self.assertRegex(vector["identifier"], rule)
                for bundle in vector["bundles"]:
                    for entry in bundle["claims"]:
                        self.assertRegex(entry["identifier"], rule)

    def test_cci_tlsn_commitment_is_the_claim_identifier(self):
        # §7.3.3 step 4: for cci-tlsn the commitment is H, on the proof and in
        # every bundle entry for the claim.
        for vector in self.document["vectors"]:
            if vector["scheme"] != "cci-tlsn":
                continue
            with self.subTest(vector=vector["name"]):
                self.assertEqual(vector["proof"]["commitment"], vector["identifier"])
                for bundle in vector["bundles"]:
                    for entry in bundle["claims"]:
                        self.assertEqual(
                            entry["tlsnotaryProofCommitment"], vector["identifier"])

    def test_integer_user_id_is_compared_as_base_10_text(self):
        vector = self.vectors["cci-tlsn-integer-user-id-subject"]
        self.assertEqual(vector["storedEntry"]["userId"], 77)
        self.assertTrue(subject_ok(vector))
        zero = self.vectors[
            "cci-tlsn-subject-with-leading-zero-is-not-the-integer-user-id"]
        self.assertEqual(zero["storedEntry"]["userId"], 77)
        self.assertEqual(zero["proof"]["subject"], "077")
        self.assertFalse(subject_ok(zero))
        for user_id in (True, -77, 2**53, 77.0, None):
            with self.subTest(user_id=user_id):
                self.assertIsNone(user_id_text(user_id))

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
        for subject in ("ß.example", "ς.example", "a\u200cb.example",
                        "a\u200db.example", "a。b.example", "\U0001f600.example",
                        "Ü.example"):
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
            "cci-tlsn-integer-user-id-subject": ("pass", None),
            "cci-tlsn-subject-with-leading-zero-is-not-the-integer-user-id": (
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
             "Session binding", "Apply the parser rules", "Subject match", "Anchor",
             "Return"],
        )
        self.assertIn("for `cci-tlsn`, the claim's identifier `H`", section)
        self.assertIn("as the TLSNotary specification defines it", section)
        self.assertIn("as PSP-1 and PSP-2 define", section)
        self.assertIn("then the match predicate", section)
        self.assertIn("`fail` where PSP-2 says no match", section)
        self.assertIn("`indeterminate` where PSP-2 or §7.5.1 gives it", section)
        self.assertIn("never turns either into `pass`", section)
        self.assertIn("as text: NFC both", section)
        self.assertIn("no sign, leading zeros or exponent", section)
        self.assertIn("applies to `H` and not to `userId`", section)
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
