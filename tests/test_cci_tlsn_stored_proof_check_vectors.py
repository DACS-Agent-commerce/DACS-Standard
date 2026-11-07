import hashlib
import json
import re
import unicodedata
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "cci-tlsn-stored-proof-check-v0.1.json"
)
SPEC = ROOT / "spec" / "DACS-2-VET.md"
HEX64 = re.compile(r"[0-9a-f]{64}")


def stored_proof_ok(vector):
    """H resolves to a stored entry and the supplied proof equals its proof."""
    entry = vector["storedEntry"]
    return entry is not None and vector["proof"]["body"] == entry["proof"]


def subject_ok(vector):
    """A declared subject equals the stored userId as JSON strings only."""
    if "subject" not in vector["recipe"]["dataMap"]:
        return True
    subject = vector["proof"]["subject"]
    user_id = vector["storedEntry"]["userId"]
    if not isinstance(subject, str) or not isinstance(user_id, str):
        return False
    return unicodedata.normalize("NFC", subject) == unicodedata.normalize("NFC", user_id)


def evaluate(vector):
    """Return (expected, failedPart) for a cci-tlsn stored-proof check vector."""
    if not stored_proof_ok(vector):
        return "fail", "stored-proof"
    if not subject_ok(vector):
        return "fail", "subject"
    return "pass", None


def spec_section():
    text = SPEC.read_text(encoding="utf-8")
    start = text.index("#### 7.3.3 tlsnotary")
    return text[start:text.index("#### 7.3.4 zktls")]


def stored_proof_paragraph():
    section = spec_section()
    start = section.index("*Stored-proof check (`cci-tlsn` only).*")
    return section[start:].split("\n\n")[0]


class CciTlsnStoredProofCheckVectorTests(unittest.TestCase):
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

    def test_every_vector_is_cci_tlsn_with_a_64_hex_lowercase_identifier(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(vector["scheme"], "cci-tlsn")
                self.assertRegex(vector["identifier"], HEX64)

    def test_every_vector_matches_the_check(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    evaluate(vector), (vector["expected"], vector["failedPart"])
                )

    def test_required_cases_are_present_with_their_results(self):
        required = {
            "stored-proof-and-string-subject-equal": ("pass", None),
            "string-subject-differs-from-user-id": ("fail", "subject"),
            "number-subject-with-string-user-id": ("fail", "subject"),
            "string-subject-with-number-user-id": ("fail", "subject"),
            "proof-stored-under-another-hash": ("fail", "stored-proof"),
            "hash-resolves-to-no-stored-entry": ("fail", "stored-proof"),
            "declared-subject-resolves-to-nothing": ("fail", "subject"),
            "no-subject-declared-stored-proof-supplied": ("pass", None),
        }
        for name, result in required.items():
            with self.subTest(vector=name):
                self.assertIn(name, self.vectors)
                vector = self.vectors[name]
                self.assertEqual((vector["expected"], vector["failedPart"]), result)

    def test_number_cases_use_json_numbers_on_the_non_string_side(self):
        number_subject = self.vectors["number-subject-with-string-user-id"]
        self.assertEqual(number_subject["proof"]["subject"], 12345)
        self.assertIsInstance(number_subject["storedEntry"]["userId"], str)
        number_user_id = self.vectors["string-subject-with-number-user-id"]
        self.assertEqual(number_user_id["storedEntry"]["userId"], 12345)
        self.assertEqual(number_user_id["proof"]["subject"], "12345")
        both_numbers = self.vectors["number-subject-with-equal-number-user-id"]
        self.assertEqual(both_numbers["proof"]["subject"], both_numbers["storedEntry"]["userId"])
        self.assertNotIsInstance(both_numbers["proof"]["subject"], str)

    def test_each_part_fails_on_its_own(self):
        for vector in self.document["vectors"]:
            if vector["failedPart"] == "stored-proof":
                with self.subTest(vector=vector["name"]):
                    self.assertFalse(stored_proof_ok(vector))
                    # the subject part would not fail here, so only stored-proof decides
                    entry = vector["storedEntry"] or {"userId": vector["proof"]["subject"]}
                    probe = dict(vector, storedEntry=dict(entry, proof=vector["proof"]["body"]))
                    self.assertTrue(subject_ok(probe))
            if vector["failedPart"] == "subject":
                with self.subTest(vector=vector["name"]):
                    self.assertTrue(stored_proof_ok(vector))
                    self.assertFalse(subject_ok(vector))

    def test_decomposed_subject_equals_precomposed_user_id_after_nfc(self):
        vector = self.vectors["subject-equal-after-nfc"]
        self.assertNotEqual(vector["proof"]["subject"], vector["storedEntry"]["userId"])
        self.assertEqual(evaluate(vector), ("pass", None))

    def test_no_subject_declared_adds_nothing_beyond_the_stored_proof_match(self):
        for vector in self.document["vectors"]:
            if "subject" not in vector["recipe"]["dataMap"]:
                with self.subTest(vector=vector["name"]):
                    self.assertEqual(
                        vector["expected"], "pass" if stored_proof_ok(vector) else "fail"
                    )

    def test_spec_restores_the_base_procedure_paragraph(self):
        section = spec_section()
        self.assertIn(
            "**Procedure.** Validates the TLSNotary proof per the TLSNotary "
            "specification (current PSE rebuild); verifies the notary signature "
            "against a known notary public key registry; if sessionTemplate is set, "
            "verifies the proof targets that endpoint and protocol; anchors the "
            "proof commitment via SR-2; applies parser rules to any disclosed "
            "segments; returns VerifyResult per outcome. **Trust model:** TLS PKI; "
            "notary honesty; MPC computational assumptions. **Substrate:** SR-2.",
            section,
        )
        self.assertIsNone(re.search(r"^\d+\. \*\*", section, flags=re.MULTILINE))
        self.assertNotIn("tlsnotaryProofCommitment", section)
        self.assertNotIn("*Outcome.*", section)

    def test_spec_paragraph_pins_the_stored_proof_check(self):
        paragraph = stored_proof_paragraph()
        self.assertIn("applies only when the requirement is on a registered `cci-tlsn:H` claim", paragraph)
        self.assertIn("anchors via SR-2, is `H`", paragraph)
        self.assertIn("stored web2 entry whose proof hash is `H`", paragraph)
        self.assertIn("MUST equal the proof stored with that entry", paragraph)
        self.assertIn("MUST reject (`fail`) if `H` resolves to no stored entry or the proofs differ", paragraph)
        self.assertIn("How the node derives `H` is outside this check", paragraph)
        self.assertIn("declares a `subject` entry", paragraph)
        self.assertIn("MUST equal the stored entry's `userId`", paragraph)
        self.assertIn("compared as JSON strings only: exact equality after NFC", paragraph)
        self.assertIn("A non-string on either side", paragraph)
        self.assertIn("resolves to nothing", paragraph)
        self.assertIn("it never yields `pass` and adds no new outcome", paragraph)
        self.assertIn("are not yet supported by this check and fail closed", paragraph)
        self.assertIn("MUST NOT convert numbers to text here", paragraph)
        self.assertIn("adds nothing beyond (1) and (2)", paragraph)
        self.assertIn("The check applies to no other scheme", paragraph)
        self.assertIn("adds no session binding, signature, signature domain or nonce use", paragraph)
        self.assertIn("other outcomes follow the procedure above unchanged", paragraph)
        self.assertIn("its `fail` stands whatever they give", paragraph)
        self.assertIn("Part (3) applies only when the parser rules would otherwise give `pass`", paragraph)
        self.assertIn("`error` or `indeterminate`, that outcome stands", paragraph)

    def test_spec_psp3_exception_is_only_the_unresolved_subject(self):
        text = SPEC.read_text(encoding="utf-8")
        psp3 = text[text.index("- (PSP-3)"):].split("\n")[0]
        self.assertIn(
            "MUST NOT by itself change the decision, except that a declared `subject` "
            "entry that resolves to nothing fails the §7.3.3 stored-proof check.",
            psp3,
        )
        self.assertNotIn("reserved", psp3)

    def test_spec_has_no_leftover_step_wording(self):
        # "Session binding" is another method's own step name (§7.3.4), so it is
        # checked only inside §7.3.3.
        text = SPEC.read_text(encoding="utf-8")
        for stale in ("step 6", "step 4", "tlsnotaryProofCommitment"):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, text)
        self.assertNotIn("Session binding", spec_section())


if __name__ == "__main__":
    unittest.main()
